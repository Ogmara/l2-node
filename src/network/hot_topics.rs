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
use std::time::Instant;

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
    /// **Distinct** contributors, `contributor_key → latest cardinality
    /// estimate`. Keyed by the sender's libp2p PeerId (base58); the local
    /// node's own contribution is keyed `"@local"`. Bounded at
    /// `digest_max_peers` — a re-fold from a peer already present REFRESHES
    /// its value and re-unions its sketch but never grows the map. This is
    /// what makes `min_contributors` a real distinct-node gate and the
    /// median trim a real cross-node median (Code+Security Audit C1).
    #[serde(default)]
    pub contributors: std::collections::BTreeMap<String, u32>,
    /// Wall-clock ms of the last update (diagnostics / eviction sanity).
    pub updated_at: u64,
}

/// Contributor key for this node's own local sketch.
pub const LOCAL_CONTRIBUTOR_KEY: &str = "@local";

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

/// A digest that has passed every synchronous validation gate and is ready to
/// be folded into `HOT_TOPICS_MERGED`. The fold itself (RocksDB read-modify-
/// write per `(bucket, tag)`) is done off the swarm event loop.
#[derive(Debug)]
pub struct ValidatedDigest {
    /// base58 libp2p PeerId of the sender — the contributor key in
    /// `HotTopicsMerged::contributors`.
    peer_key: String,
    buckets: Vec<DigestBucket>,
    now_ms: u64,
}

/// Outcome of classifying + validating a `/network`-topic message.
#[derive(Debug)]
pub enum InboundDecision {
    /// Not a Hot Topics digest — the caller falls through to the generic
    /// envelope router (e.g. a `NodeAnnouncement`).
    NotADigest,
    /// Validated — report `Accept` and fold [`ValidatedDigest`] off-loop.
    Fold(Box<ValidatedDigest>),
    /// Structurally/cryptographically invalid — reject + penalize the relay.
    Reject(String),
    /// Well-formed but not folded (untrusted sender, rate-limited, out of
    /// window). Ignore, do not penalize.
    Ignore(String),
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
    /// PeerId → last accepted-OR-rejected digest `Instant` (a bad digest also
    /// arms the limiter, so a peer flooding malformed digests is throttled
    /// after the first).
    rate: Mutex<HashMap<PeerId, Instant>>,
    /// libp2p **PeerIds** whose digests may be folded — the sender-identity
    /// gate (Code+Security Audit C1). Populated from the SC `getActiveNodes`
    /// set cross-referenced with each node's on-chain published multiaddrs
    /// (`/p2p/<peer_id>`), so a digest's `peer_id` — which is already bound to
    /// the signature and matched against the gossip propagation source — is
    /// what decides trust, NOT the self-asserted `node_address` string.
    /// Refreshed by `NetworkService`/`node.rs`.
    trusted_peers: RwLock<HashSet<PeerId>>,
    /// `(computed_at, result)` — TTL `config.cache_ttl_secs`.
    result_cache: Mutex<Option<(Instant, HotTopicsResult)>>,
    /// Serializes `compute_query` so concurrent cache misses don't each run
    /// the full window scan (single-flight).
    compute_lock: Mutex<()>,
}

impl HotTopicsAggregator {
    pub fn new(storage: Storage, config: HotTopicsConfig, network_id: impl Into<String>) -> Self {
        Self {
            storage,
            config,
            network_id: network_id.into(),
            rate: Mutex::new(HashMap::new()),
            trusted_peers: RwLock::new(HashSet::new()),
            result_cache: Mutex::new(None),
            compute_lock: Mutex::new(()),
        }
    }

    pub fn config(&self) -> &HotTopicsConfig {
        &self.config
    }

    /// Replace the trusted-PeerId set (SC-registered active nodes whose
    /// on-chain multiaddrs we could resolve to a PeerId). Called only after a
    /// clean, complete `getActiveNodes` pagination.
    pub fn set_trusted_peers(&self, set: HashSet<PeerId>) {
        if let Ok(mut g) = self.trusted_peers.write() {
            *g = set;
        }
    }

    fn have_trusted_peers(&self) -> bool {
        self.trusted_peers.read().map(|g| !g.is_empty()).unwrap_or(false)
    }

    fn is_trusted_peer(&self, peer: &PeerId) -> bool {
        self.trusted_peers.read().map(|g| g.contains(peer)).unwrap_or(false)
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
                if val.len() > self.config.max_sketch_bytes {
                    continue;
                }
                let Some((_, tag)) = schema::decode_hot_topics_key(&key) else { continue };
                let Some(hll) = Hll::from_bytes(&val) else { continue };
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

    /// Cheap first-look classifier for a `/network`-topic message: is the first
    /// byte a MessagePack `fixmap`/`map16`/`map32` marker? Both a
    /// `NodeAnnouncement` envelope and a digest are maps, so this only rejects
    /// obviously-non-map frames without a full decode; the real distinction is
    /// made by [`classify_and_validate`] which tries the strict digest decode.
    fn is_mapish(bytes: &[u8]) -> bool {
        match bytes.first() {
            Some(&b) => (0x80..=0x8f).contains(&b) || b == 0xde || b == 0xdf,
            None => false,
        }
    }

    /// Classify + fully validate a `/network`-topic message. Everything here is
    /// synchronous and cheap enough for the swarm event loop; the actual fold
    /// (RocksDB read-modify-write per `(bucket, tag)`) is returned to the
    /// caller as a [`ValidatedDigest`] to run off-loop. Cost-ordered like
    /// `presence::validate_record`.
    pub fn classify_and_validate(
        &self,
        propagation_source: PeerId,
        bytes: &[u8],
        now_ms: u64,
    ) -> InboundDecision {
        // 0. Size guard (pre-decode) + cheap shape pre-check.
        if bytes.len() > self.config.digest_max_envelope_bytes || !Self::is_mapish(bytes) {
            return InboundDecision::NotADigest;
        }
        // 1. Strict decode — a NodeAnnouncement envelope lacks the required
        //    fields and lands here as NotADigest (caller falls through).
        let digest: HotTopicsDigest = match rmp_serde::from_slice(bytes) {
            Ok(d) => d,
            Err(_) => return InboundDecision::NotADigest,
        };
        let s = &digest.signed;
        if s.msg_type != HOT_TOPICS_DIGEST_TAG {
            return InboundDecision::NotADigest;
        }
        // From here it IS a digest — decide accept/reject/ignore.
        if !self.config.enabled || !self.config.mesh_enabled {
            return InboundDecision::Ignore("mesh disabled".into());
        }
        // 2. PeerId parse + denylist + propagation-source match.
        let claimed: PeerId = match s.peer_id.parse() {
            Ok(p) => p,
            Err(e) => return InboundDecision::Reject(format!("bad peer_id: {e}")),
        };
        if self.config.digest_denylist.iter().any(|d| d == &s.peer_id) {
            return InboundDecision::Ignore("denylisted".into());
        }
        if claimed != propagation_source {
            return InboundDecision::Reject("peer_id != propagation source".into());
        }
        // 3. Rate limit — check AND arm in one step, BEFORE the expensive
        //    signature verify, so a peer flooding digests (valid or not) pays
        //    one verify then is throttled for `inbound_rate_limit_secs`.
        if !self.rate_check_and_commit(&claimed) {
            return InboundDecision::Ignore("rate limited".into());
        }
        // 4. Timestamp skew.
        let now_s = unix_secs(now_ms);
        if s.timestamp <= now_s.saturating_sub(DIGEST_PAST_SKEW_SECS)
            || s.timestamp >= now_s.saturating_add(DIGEST_FUTURE_SKEW_SECS)
        {
            return InboundDecision::Reject("timestamp skew".into());
        }
        // 5. network_id.
        if s.network_id != self.network_id {
            return InboundDecision::Reject("network_id mismatch".into());
        }
        // 6. window_hours.
        if s.window_hours != self.config.window_hours {
            return InboundDecision::Ignore("window_hours mismatch".into());
        }
        // 7. Shape caps.
        if s.buckets.len() > self.config.max_buckets_per_digest {
            return InboundDecision::Reject("too many buckets".into());
        }
        if s.buckets.iter().any(|b| b.tags.len() > self.config.max_tags_per_digest) {
            return InboundDecision::Reject("too many tags in a bucket".into());
        }
        // 8. Signature (Ed25519 over to_vec_named(signed)).
        if let Err(e) = verify_digest_sig(&digest) {
            return InboundDecision::Reject(format!("bad signature: {e}"));
        }
        // 9. Sender-identity gate — the digest's `peer_id` (bound to the
        //    signature AND matched to the gossip source) MUST be a
        //    SC-registered active node's PeerId. `node_address` is advisory
        //    only. When we have no trusted set at all (Klever RPC not
        //    configured, or the SC nodes publish no multiaddrs) we cannot
        //    verify anyone → do NOT fold; this node still serves its own
        //    local view (Code+Security Audit C1).
        if self.config.require_sc_registered_sender {
            if !self.have_trusted_peers() {
                return InboundDecision::Ignore("no trusted-peer set — folding disabled".into());
            }
            if !self.is_trusted_peer(&claimed) {
                return InboundDecision::Ignore("sender is not an SC-registered active node".into());
            }
        }
        // 10. Keep only in-window buckets; the caller folds off-loop.
        let lo = self.window_lo_bucket(now_ms);
        let hi = Self::current_bucket(now_ms) + 1;
        let peer_key = s.peer_id.clone();
        let buckets: Vec<DigestBucket> = digest
            .signed
            .buckets
            .into_iter()
            .filter(|b| b.bucket_hour >= lo && b.bucket_hour <= hi)
            .collect();
        if buckets.is_empty() {
            return InboundDecision::Ignore("no in-window buckets".into());
        }
        InboundDecision::Fold(Box::new(ValidatedDigest {
            peer_key,
            buckets,
            now_ms,
        }))
    }

    /// Fold a fully-validated digest into `HOT_TOPICS_MERGED`. Runs off the
    /// swarm event loop (`spawn_blocking`). Contributor identity is the
    /// sender's PeerId, so re-folds from the same peer refresh rather than
    /// inflate (Code+Security Audit C1).
    pub fn fold(&self, vd: ValidatedDigest) {
        let mut folded = 0usize;
        for b in &vd.buckets {
            for t in &b.tags {
                if crate::util::normalize_tag(&t.tag).as_deref() != Some(t.tag.as_str()) {
                    continue; // non-canonical tag in a digest — skip
                }
                if t.hll.len() > self.config.max_sketch_bytes {
                    continue;
                }
                let Some(incoming) = Hll::from_bytes(&t.hll) else { continue };
                // Bound BOTH the self-reported estimate AND the sketch's own
                // estimate — a sender can pass a small `approx` alongside a
                // saturated sketch (Code W6 / Security C2).
                let est = incoming.estimate_u32().max(t.approx);
                if est > self.config.max_node_tag_contribution.saturating_mul(2) {
                    warn!(peer = %vd.peer_key, tag = %t.tag, est, "hot-topics: dropping wildly-inflated tag from digest");
                    continue;
                }
                if est > self.config.max_node_tag_contribution {
                    warn!(peer = %vd.peer_key, tag = %t.tag, est, "hot-topics: peer contribution above clamp (folding anyway)");
                }
                let clamped = est.min(self.config.max_node_tag_contribution);
                if let Err(e) =
                    self.fold_one(b.bucket_hour, &t.tag, &incoming, &vd.peer_key, clamped, vd.now_ms)
                {
                    debug!(error = %e, "hot-topics: fold failed");
                }
                folded += 1;
            }
        }
        debug!(peer = %vd.peer_key, folded, "hot-topics: digest folded");
        // Note: the result cache is NOT invalidated here — a <= cache_ttl_secs
        // stale trending list is fine, and invalidating on every fold makes a
        // busy mesh recompute the full window scan on every request (Code W2 /
        // Security W2).
    }

    #[allow(clippy::too_many_arguments)]
    fn fold_one(
        &self,
        bucket_hour: u64,
        tag: &str,
        incoming: &Hll,
        peer_key: &str,
        approx: u32,
        now_ms: u64,
    ) -> Result<()> {
        let key = schema::encode_hot_topics_key(bucket_hour, tag);
        let existing = self.storage.get_cf(schema::cf::HOT_TOPICS_MERGED, &key)?;

        // Per-bucket distinct-tag cap on the MERGED CF too, not just LOCAL
        // (Code+Security Audit W3/W7): a fresh tag is dropped once the bucket
        // is full; tags already tracked keep folding.
        if existing.is_none() {
            let tracked = self.storage.count_prefix_cf(
                schema::cf::HOT_TOPICS_MERGED,
                &bucket_hour.to_be_bytes(),
                self.config.max_tracked_tags_per_bucket.saturating_add(1),
            )?;
            if tracked as usize >= self.config.max_tracked_tags_per_bucket {
                return Ok(());
            }
        }

        let mut merged: HotTopicsMerged = existing
            .and_then(|b| rmp_serde::from_slice(&b).ok())
            .unwrap_or_default();

        // Seed from local on first touch so the merged view is never behind
        // this node's own ingest — recorded as the `@local` contributor.
        let mut acc = if merged.merged_hll.is_empty() {
            let local = self
                .storage
                .get_cf(schema::cf::HOT_TOPICS_LOCAL, &key)?
                .and_then(|b| Hll::from_bytes(&b))
                .unwrap_or_default();
            if !local.is_empty() {
                merged
                    .contributors
                    .insert(LOCAL_CONTRIBUTOR_KEY.to_string(), local.estimate_u32());
            }
            local
        } else {
            Hll::from_bytes(&merged.merged_hll).unwrap_or_default()
        };

        acc.merge(incoming);
        merged.merged_hll = acc.to_bytes();
        // Record/refresh this contributor. Bounded at digest_max_peers — a new
        // peer beyond the cap is dropped (its sketch is still unioned above, so
        // it can't be undone, but it doesn't grow the distinct-contributor
        // count / median input).
        let cap = self.config.digest_max_peers.max(1);
        if merged.contributors.contains_key(peer_key) || merged.contributors.len() < cap {
            merged.contributors.insert(peer_key.to_string(), approx);
        }
        merged.updated_at = now_ms;

        let bytes = rmp_serde::to_vec_named(&merged)?;
        self.storage
            .put_cf(schema::cf::HOT_TOPICS_MERGED, &key, &bytes)?;
        Ok(())
    }

    /// Check the per-PeerId rate limit and, on success, arm it. A digest that
    /// later turns out invalid still consumed this slot, so a peer flooding
    /// malformed digests is throttled after the first.
    fn rate_check_and_commit(&self, peer: &PeerId) -> bool {
        let gap = std::time::Duration::from_secs(self.config.inbound_rate_limit_secs.max(1));
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

    // --- Query ---

    /// Compute (or serve from the TTL cache) the top-N trending tags.
    /// Single-flight: concurrent cache misses serialize on `compute_lock` so
    /// only one full window scan runs at a time.
    pub fn query(&self, limit: usize, now_ms: u64) -> HotTopicsResult {
        let ttl = std::time::Duration::from_secs(self.config.cache_ttl_secs.max(1));
        let fresh = |g: &Option<(Instant, HotTopicsResult)>| {
            g.as_ref().filter(|(at, _)| at.elapsed() < ttl).map(|(_, r)| r.clone())
        };
        if let Ok(g) = self.result_cache.lock() {
            if let Some(mut r) = fresh(&g) {
                r.topics.truncate(limit);
                return r;
            }
        }
        let _flight = self.compute_lock.lock();
        // Another waiter may have populated the cache while we blocked.
        if let Ok(g) = self.result_cache.lock() {
            if let Some(mut r) = fresh(&g) {
                r.topics.truncate(limit);
                return r;
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
        // Per-bucket scan cap: distinct tags per bucket are bounded by
        // max_tracked_tags_per_bucket on both write paths, so this is a
        // safety ceiling, not the expected size.
        let scan_cap = self.config.max_tracked_tags_per_bucket.saturating_mul(2).max(1024);

        // tag -> (window-union HLL, contributor_key -> max approx)
        let mut merged_acc: HashMap<String, (Hll, std::collections::BTreeMap<String, u32>)> =
            HashMap::new();
        let mut local_acc: HashMap<String, Hll> = HashMap::new();

        for bh in lo..=cur {
            let prefix = bh.to_be_bytes();
            if let Ok(rows) =
                self.storage
                    .prefix_iter_cf(schema::cf::HOT_TOPICS_MERGED, &prefix, scan_cap)
            {
                for (key, val) in rows {
                    let Some((_, tag)) = schema::decode_hot_topics_key(&key) else { continue };
                    let Ok(m) = rmp_serde::from_slice::<HotTopicsMerged>(&val) else { continue };
                    let Some(hll) = Hll::from_bytes(&m.merged_hll) else { continue };
                    let e = merged_acc
                        .entry(tag.to_string())
                        .or_insert_with(|| (Hll::new(), std::collections::BTreeMap::new()));
                    e.0.merge(&hll);
                    for (k, v) in m.contributors {
                        let slot = e.1.entry(k).or_insert(0);
                        *slot = (*slot).max(v);
                    }
                }
            }
            if let Ok(rows) =
                self.storage
                    .prefix_iter_cf(schema::cf::HOT_TOPICS_LOCAL, &prefix, scan_cap)
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
                Some((hll, contribs)) => {
                    let raw = hll.estimate_u32() as u64;
                    // Distinct non-local contributors — the gate + trim input.
                    let n_distinct = contribs.len() as u16;
                    let mut approxes: Vec<u64> = contribs
                        .iter()
                        .filter(|(k, _)| k.as_str() != LOCAL_CONTRIBUTOR_KEY)
                        .map(|(_, v)| *v as u64)
                        .collect();
                    approxes.sort_unstable();
                    let trimmed = if approxes.len() as u16 >= self.config.min_contributors_for_trim {
                        let median = approxes[approxes.len() / 2];
                        raw.min(median.saturating_mul(self.config.trim_multiplier as u64))
                    } else {
                        // Too few distinct peers for a stable median → bound by
                        // local cardinality × multiplier.
                        raw.min(
                            local_est.saturating_mul(self.config.local_only_multiplier as u64),
                        )
                    };
                    (trimmed.max(local_est), n_distinct)
                }
                None => (local_est, if local_est > 0 { 1 } else { 0 }),
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

    /// `NODE_STATE` key: set once the first-start bootstrap has run so a
    /// low-traffic node whose buckets all legitimately evict doesn't re-scan
    /// the whole feed on every boot (Code+Security Audit W8).
    const BOOTSTRAP_DONE_KEY: &'static [u8] = b"hot_topics_bootstrapped";

    /// On first start after upgrade: if we've never bootstrapped and
    /// `HOT_TOPICS_LOCAL` is empty, rebuild the local sketches from the last
    /// `window_hours` of PUBLIC news posts, then persist the done-marker.
    /// Streams `NEWS_FEED` in bounded batches and flushes per bucket so a
    /// huge history never buffers all sketches at once. Returns the number of
    /// posts scanned.
    pub fn bootstrap_local_from_news_feed(&self, now_ms: u64) -> Result<u64> {
        if !self.config.enabled {
            return Ok(0);
        }
        if self
            .storage
            .get_cf(schema::cf::NODE_STATE, Self::BOOTSTRAP_DONE_KEY)?
            .is_some()
        {
            return Ok(0);
        }
        let already = self
            .storage
            .prefix_iter_cf(schema::cf::HOT_TOPICS_LOCAL, &[], 1)?;
        if !already.is_empty() {
            // Sketches already exist (a running 0.124.0 node) — just mark done.
            self.storage
                .put_cf(schema::cf::NODE_STATE, Self::BOOTSTRAP_DONE_KEY, &[1])?;
            return Ok(0);
        }
        let lo_bucket = Self::current_bucket(now_ms)
            .saturating_sub(self.config.window_hours + self.config.eviction_slack_hours);
        let lo_ms = lo_bucket.saturating_mul(HOT_TOPICS_BUCKET_MS);
        let tag_cap = self.config.max_tracked_tags_per_bucket;

        // NEWS_FEED is keyed by `!timestamp` (newest first). Walk from the head
        // in batches; every post in a batch is in the same or an earlier hour
        // than the previous, so once we cross `lo_ms` we're done.
        let mut scanned = 0u64;
        // Only the CURRENT bucket's sketches are held in memory; flushed when
        // the scan moves to an older bucket.
        let mut cur_bucket: Option<u64> = None;
        let mut cur_sketches: HashMap<String, Hll> = HashMap::new();
        let flush = |bh: u64, sk: &mut HashMap<String, Hll>, storage: &Storage| -> Result<()> {
            for (tag, hll) in sk.drain() {
                storage.put_cf(
                    schema::cf::HOT_TOPICS_LOCAL,
                    &schema::encode_hot_topics_key(bh, &tag),
                    &hll.to_bytes(),
                )?;
            }
            Ok(())
        };

        let mut start: Vec<u8> = Vec::new();
        'scan: loop {
            let batch = if start.is_empty() {
                self.storage.prefix_iter_cf(schema::cf::NEWS_FEED, &[], 4096)?
            } else {
                self.storage
                    .prefix_iter_cf_after(schema::cf::NEWS_FEED, &start, &[], 4096)?
            };
            if batch.is_empty() {
                break;
            }
            for (key, _) in &batch {
                start = key.clone();
                if key.len() < 40 {
                    continue;
                }
                let inv_ts = u64::from_be_bytes(key[0..8].try_into().unwrap_or([0; 8]));
                let ts = !inv_ts;
                if ts < lo_ms {
                    break 'scan;
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
                let Ok(payload) = rmp_serde::from_slice::<
                    crate::messages::types::NewsPostPayload,
                >(&env.payload) else {
                    continue;
                };
                // Public-only, mirroring the ingest path (Security Audit N1).
                if payload.visibility != crate::messages::types::Visibility::Public {
                    continue;
                }
                let bh = env.timestamp / HOT_TOPICS_BUCKET_MS;
                if cur_bucket != Some(bh) {
                    if let Some(prev) = cur_bucket {
                        flush(prev, &mut cur_sketches, &self.storage)?;
                    }
                    cur_bucket = Some(bh);
                }
                for tag in crate::util::normalize_tags_dedup(&payload.tags) {
                    if !cur_sketches.contains_key(&tag) && cur_sketches.len() >= tag_cap {
                        continue; // per-bucket distinct-tag cap
                    }
                    cur_sketches.entry(tag).or_default().insert(&msg_id);
                }
                scanned += 1;
            }
        }
        if let Some(bh) = cur_bucket {
            flush(bh, &mut cur_sketches, &self.storage)?;
        }
        self.storage
            .put_cf(schema::cf::NODE_STATE, Self::BOOTSTRAP_DONE_KEY, &[1])?;
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

/// Current wall-clock ms since the epoch — re-exported from `util` so callers
/// in the network layer don't reach across modules for it.
pub use crate::util::now_ms;

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

    /// Deliver a digest to `receiver` as the network layer would: classify +
    /// validate, and on `Fold` also run the fold. Returns the decision.
    fn deliver(
        receiver: &HotTopicsAggregator,
        src: PeerId,
        bytes: &[u8],
        now: u64,
    ) -> InboundDecision {
        let d = receiver.classify_and_validate(src, bytes, now);
        if let InboundDecision::Fold(vd) = d {
            let vd = *vd;
            let key = vd.peer_key.clone();
            receiver.fold(vd);
            return InboundDecision::Fold(Box::new(ValidatedDigest {
                peer_key: key,
                buckets: vec![],
                now_ms: now,
            }));
        }
        d
    }

    fn trust(receiver: &HotTopicsAggregator, peer: PeerId) {
        let mut cur: HashSet<PeerId> = receiver
            .trusted_peers
            .read()
            .map(|g| g.clone())
            .unwrap_or_default();
        cur.insert(peer);
        receiver.set_trusted_peers(cur);
    }

    #[test]
    fn digest_fold_from_five_nodes_counts_the_union_once() {
        // Five nodes each ingest the SAME 100 posts under #klever. The merged
        // estimate must be ~100, not ~500 — the whole point of the design —
        // and each distinct peer counts once toward the contributor gate.
        let now = 2_000 * HOT_TOPICS_BUCKET_MS + 1;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        let (receiver, _d) = agg(HotTopicsConfig::default());

        for node in 0..5u64 {
            let (sender, _sd) = agg(HotTopicsConfig::default());
            put_local(&sender, cur, "klever", &(0..100).collect::<Vec<_>>());
            let kp = libp2p::identity::Keypair::generate_ed25519();
            let src = kp.public().to_peer_id();
            trust(&receiver, src);
            let bytes = sender
                .build_and_sign_digest(&kp, &format!("klv1node{node}"), now)
                .expect("digest");
            let d = deliver(&receiver, src, &bytes, now + node);
            assert!(matches!(d, InboundDecision::Fold(_)), "node {node}: {d:?}");
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
    fn one_peer_resending_does_not_inflate_the_contributor_count() {
        // Code+Security Audit C1: the SAME peer folding its digest repeatedly
        // must stay ONE contributor, so a lone node can't reach the
        // min_contributors_for_trim (3) regime by itself.
        let mut cfg = HotTopicsConfig::default();
        cfg.min_contributors_for_trim = 3;
        cfg.local_only_multiplier = 4;
        let now = 9_000 * HOT_TOPICS_BUCKET_MS + 1;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        let (receiver, _d) = agg(cfg);
        // receiver has NO local posts for #forge → local_est is 0.
        let (sender, _sd) = agg(HotTopicsConfig::default());
        put_local(&sender, cur, "forge", &(0..5000).collect::<Vec<_>>());
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let src = kp.public().to_peer_id();
        trust(&receiver, src);

        // Fold the same peer's digest three times (bypassing the rate limiter
        // by folding the ValidatedDigest directly).
        for _ in 0..3 {
            let bytes = sender.build_and_sign_digest(&kp, "klv1lonewolf", now).unwrap();
            if let InboundDecision::Fold(vd) =
                receiver.classify_and_validate(src, &bytes, now)
            {
                receiver.fold(*vd);
            }
            // clear the rate slot so the next classify passes
            receiver.rate.lock().unwrap().clear();
        }

        let key = schema::encode_hot_topics_key(cur, "forge");
        let m: HotTopicsMerged = rmp_serde::from_slice(
            &receiver
                .storage
                .get_cf(schema::cf::HOT_TOPICS_MERGED, &key)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(m.contributors.len(), 1, "one distinct peer, not three folds");

        // With <3 distinct peers and local_est 0, the trim bounds count to
        // local_est * multiplier = 0 → the forged tag is filtered by min_count.
        let res = receiver.query(10, now);
        assert!(
            res.topics.iter().all(|t| t.hashtag != "forge"),
            "a lone peer forged a network-scope tag: {:?}",
            res.topics
        );
    }

    #[test]
    fn untrusted_peer_is_ignored_not_folded() {
        let now = 3_000 * HOT_TOPICS_BUCKET_MS + 1;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        let (sender, _sd) = agg(HotTopicsConfig::default());
        put_local(&sender, cur, "klever", &(0..100).collect::<Vec<_>>());
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let bytes = sender.build_and_sign_digest(&kp, "klv1rogue", now).unwrap();

        let (receiver, _d) = agg(HotTopicsConfig::default());
        // Non-empty trusted set, but WITHOUT the sender's PeerId.
        trust(&receiver, libp2p::identity::Keypair::generate_ed25519().public().to_peer_id());
        let d = deliver(&receiver, kp.public().to_peer_id(), &bytes, now);
        assert!(matches!(d, InboundDecision::Ignore(_)), "{d:?}");
    }

    #[test]
    fn no_trusted_set_means_fold_nothing() {
        // Security Audit C1: with no trusted-peer set (Klever RPC absent) the
        // gate must NOT accept-all — it folds nothing.
        let now = 8_000 * HOT_TOPICS_BUCKET_MS + 1;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        let (sender, _sd) = agg(HotTopicsConfig::default());
        put_local(&sender, cur, "klever", &(0..50).collect::<Vec<_>>());
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let bytes = sender.build_and_sign_digest(&kp, "klv1x", now).unwrap();
        let (receiver, _d) = agg(HotTopicsConfig::default()); // trusted set empty
        let d = deliver(&receiver, kp.public().to_peer_id(), &bytes, now);
        assert!(matches!(d, InboundDecision::Ignore(_)), "{d:?}");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let now = 4_000 * HOT_TOPICS_BUCKET_MS + 1;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        let (sender, _sd) = agg(HotTopicsConfig::default());
        put_local(&sender, cur, "klever", &[1, 2, 3, 4, 5]);
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let bytes = sender.build_and_sign_digest(&kp, "klv1x", now).unwrap();
        // Decode, corrupt a signature byte, re-encode — structure stays valid
        // so this exercises the signature check, not the decode path.
        let mut digest: HotTopicsDigest = rmp_serde::from_slice(&bytes).unwrap();
        digest.signature[10] ^= 0xFF;
        let bytes = rmp_serde::to_vec_named(&digest).unwrap();
        let (receiver, _d) = agg(HotTopicsConfig::default());
        trust(&receiver, kp.public().to_peer_id());
        let d = receiver.classify_and_validate(kp.public().to_peer_id(), &bytes, now);
        assert!(matches!(d, InboundDecision::Reject(_)), "{d:?}");
    }

    #[test]
    fn wrong_network_is_rejected() {
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
        let d = receiver.classify_and_validate(kp.public().to_peer_id(), &bytes, now);
        assert!(matches!(d, InboundDecision::Reject(_)), "{d:?}");
    }

    #[test]
    fn spoofed_propagation_source_is_rejected() {
        let now = 10_500 * HOT_TOPICS_BUCKET_MS + 1;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        let (sender, _sd) = agg(HotTopicsConfig::default());
        put_local(&sender, cur, "klever", &[1, 2, 3]);
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let bytes = sender.build_and_sign_digest(&kp, "klv1x", now).unwrap();
        let (receiver, _d) = agg(HotTopicsConfig::default());
        // Deliver claiming a DIFFERENT peer as the propagation source.
        let other = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let d = receiver.classify_and_validate(other, &bytes, now);
        assert!(matches!(d, InboundDecision::Reject(_)), "{d:?}");
    }

    #[test]
    fn rate_limit_blocks_a_rapid_second_digest() {
        let now = 6_000 * HOT_TOPICS_BUCKET_MS + 1;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        let (sender, _sd) = agg(HotTopicsConfig::default());
        put_local(&sender, cur, "klever", &(0..20).collect::<Vec<_>>());
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let src = kp.public().to_peer_id();
        let (receiver, _d) = agg(HotTopicsConfig::default());
        trust(&receiver, src);
        let b1 = sender.build_and_sign_digest(&kp, "klv1n", now).unwrap();
        let b2 = sender.build_and_sign_digest(&kp, "klv1n", now + 1).unwrap();
        assert!(matches!(
            receiver.classify_and_validate(src, &b1, now),
            InboundDecision::Fold(_)
        ));
        assert!(matches!(
            receiver.classify_and_validate(src, &b2, now + 1),
            InboundDecision::Ignore(_)
        ));
    }

    #[test]
    fn a_non_digest_network_message_is_not_a_digest() {
        let (receiver, _d) = agg(HotTopicsConfig::default());
        let src = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        // A msgpack map that is not a digest (no required fields).
        let bytes = rmp_serde::to_vec_named(&serde_json::json!({ "node_id": "x" })).unwrap();
        assert!(matches!(
            receiver.classify_and_validate(src, &bytes, 1_000),
            InboundDecision::NotADigest
        ));
        // Garbage.
        assert!(matches!(
            receiver.classify_and_validate(src, &[1, 2, 3], 1_000),
            InboundDecision::NotADigest
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
