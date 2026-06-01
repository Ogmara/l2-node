//! Presence-gossip subsystem (spec 13 §10, l2-node 0.48.0+).
//!
//! Off-chain, opt-in discovery channel that lets service-provider
//! operators advertise themselves to clients **without** committing to
//! on-chain anchoring economics (spec 12 §6.1). The subsystem runs in
//! parallel to the SC-based discovery tier (spec 13 §4): a node may
//! participate in either, both, or neither.
//!
//! ## Flow
//!
//! 1. When `[network.presence] enabled = true` AND `[api] public_url`
//!    is set, the node periodically signs a [`PresenceRecord`] with its
//!    libp2p Ed25519 key and publishes it on the gossipsub topic
//!    `/ogmara/{network_id}/presence/v1`.
//! 2. Receiving nodes verify the signature against the public key
//!    extracted from the broadcaster's `PeerId` (libp2p Ed25519 PeerIds
//!    are content-addressed inline-hashed public keys — no external
//!    trust anchor required), apply the validation rules in spec 13
//!    §10.3, and either Accept (caches + relays) or Reject (drops).
//! 3. The local in-memory [`PresenceCache`] holds at most 4_096
//!    records, evicting the oldest 10 % by `last_heard` when full and
//!    emitting a `warn!` (Sybil-flood signal). Records also expire on
//!    a TTL basis via a background sweep.
//!
//! ## Wire-format canonicalization
//!
//! Signing operates over msgpack with **named fields**
//! (`rmp_serde::to_vec_named`), aligning with the cross-language
//! convention used elsewhere in the node. The signed payload is a
//! `PresenceRecordSigned` — the full record minus the `signature`
//! field — so signers never need to "zero out" a field before signing
//! (the most common cross-language footgun).
//!
//! ## Sybil defences
//!
//! - Topic-validation hook (verify + timestamp + TTL + URL + denylist
//!   + per-peer rate limit). Failures call
//!   `gossipsub.report_message_validation_result(_, _, Reject)` to
//!   penalize the sending peer's score.
//! - In-memory cache cap of 4 096 records with oldest-by-`last_heard`
//!   eviction (flood records sort to the top of the eviction list the
//!   moment legitimate records are re-broadcast).
//! - Per-PeerId rate limit of 1 accepted record per minute.
//! - Operator-configurable denylist (`[network.presence] denylist`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Hard cap on cached presence records (spec 13 §10.4). When the cap
/// is reached the oldest 10 % by `last_heard` is evicted and a `warn!`
/// is emitted — the Sybil-flood signal.
pub const PRESENCE_CACHE_CAP: usize = 4_096;

/// Spec 13 §10.3: maximum allowed `ttl_secs` in any incoming record.
pub const PRESENCE_MAX_TTL_SECS: u32 = 7 * 24 * 3600; // 7 days

/// Spec 13 §10.3: clock-skew tolerance for incoming `timestamp` values
/// — must lie in `(now - PAST_SKEW, now + FUTURE_SKEW)`.
pub const PRESENCE_PAST_SKEW_SECS: u64 = 3600; // 1 hour
pub const PRESENCE_FUTURE_SKEW_SECS: u64 = 300; // 5 minutes

/// Spec 13 §10.3: per-PeerId rate limit (≤ 1 accepted record per minute).
pub const PRESENCE_RATE_LIMIT: Duration = Duration::from_secs(60);

/// Background TTL-sweep cadence (spec 13 §10.4).
pub const PRESENCE_SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// Security Audit W2 (v0.48.0): soft cap on the per-PeerId rate-limit
/// map. New PeerIds are refused once the map reaches this size; the
/// 5-min `prune` sweep then trims the map back. Sized 4× the cache cap
/// so legitimate churn (records expiring + new peers joining within
/// the sweep window) doesn't hit the cap, but a Sybil flood with
/// millions of unique PeerIds cannot grow the map between prunes.
pub const PRESENCE_RATE_LIMITER_SOFT_CAP: usize = 16_384;

/// Security Audit W4 (v0.48.0): per-message envelope size cap applied
/// BEFORE msgpack decode + signature verify, so an attacker cannot
/// force expensive deserialization with a 256 KB payload of valid
/// msgpack garbage. A well-formed record with all field caps applied
/// (`version` ≤ 64 bytes, `public_url` ≤ 2048 bytes, signature 64
/// bytes, plus PeerId base58 and integer fields) sits well under
/// 4 KB. 8 KB gives a generous margin for serializer overhead.
pub const PRESENCE_MAX_ENVELOPE_BYTES: usize = 8 * 1024;

/// Wire-format presence record (spec 13 §10.2). Broadcast on the
/// `/ogmara/{network_id}/presence/v1` gossipsub topic. Serialized via
/// `rmp_serde::to_vec_named` for cross-language compatibility.
///
/// The `signature` field is an Ed25519 signature over the
/// canonical bytes of [`PresenceRecordSigned`] (i.e. this record minus
/// the `signature` itself), using the libp2p private key whose public
/// key produces `peer_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceRecord {
    /// Base58-encoded libp2p PeerId of the originator.
    pub peer_id: String,
    /// Public HTTPS URL of the node's REST API, if any. `None` means
    /// "exists but no public REST endpoint" — useful for nodes that
    /// only serve gossip-mesh traffic. Must be either `https://` or
    /// `http://*.onion/` (validated server-side per spec 13 §10.3).
    pub public_url: Option<String>,
    /// Semver string of the broadcasting node (`MAJOR.MINOR.PATCH`).
    pub version: String,
    /// Unix-seconds at which the record was minted.
    pub timestamp: u64,
    /// Validity window in seconds. Default 24h, max 7d (spec 13 §10.3).
    pub ttl_secs: u32,
    /// Ed25519 signature (64 bytes) over the canonical
    /// msgpack-named-fields encoding of [`PresenceRecordSigned`].
    ///
    /// Encoded as a plain `Vec<u8>` (msgpack array-of-u8) rather than
    /// the `bin` family — both signers and verifiers go through the
    /// same serde derive, so the encoding round-trips cleanly. The
    /// signature itself is computed over the signing-payload bytes
    /// only, NOT over the encoded `PresenceRecord` containing this
    /// field, so the `Vec<u8>` vs `bin` distinction has no effect on
    /// cryptographic validity.
    pub signature: Vec<u8>,
}

/// Canonical "signing payload" — the [`PresenceRecord`] minus the
/// `signature` field. Signing operates over the
/// `rmp_serde::to_vec_named` encoding of this struct, NOT over a
/// zero-signature copy of [`PresenceRecord`]. This avoids the
/// cross-language "did the signer / verifier blank the field the same
/// way" footgun.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceRecordSigned {
    pub peer_id: String,
    pub public_url: Option<String>,
    pub version: String,
    pub timestamp: u64,
    pub ttl_secs: u32,
}

impl PresenceRecord {
    /// Strip the signature, returning the canonical signing payload.
    pub fn to_signing_payload(&self) -> PresenceRecordSigned {
        PresenceRecordSigned {
            peer_id: self.peer_id.clone(),
            public_url: self.public_url.clone(),
            version: self.version.clone(),
            timestamp: self.timestamp,
            ttl_secs: self.ttl_secs,
        }
    }

    /// Compute the absolute expiry instant (`timestamp + ttl_secs`) as
    /// unix-seconds. Saturating arithmetic — far-future records cap at
    /// `u64::MAX` rather than wrapping.
    pub fn expires_at(&self) -> u64 {
        self.timestamp.saturating_add(self.ttl_secs as u64)
    }
}

/// Errors surfaced by the presence-record validation pipeline (spec 13
/// §10.3). Each variant maps onto a topic-validation rejection
/// outcome.
#[derive(Debug, Clone, Error)]
pub enum PresenceError {
    #[error("envelope size {0} bytes exceeds the {1}-byte cap (W4)")]
    EnvelopeTooLarge(usize, usize),
    #[error("msgpack decode failed: {0}")]
    Decode(String),
    #[error("invalid peer_id in record: {0}")]
    InvalidPeerId(String),
    #[error("peer_id is on the operator denylist")]
    Denylisted,
    #[error("record peer_id does not match the originating gossip peer")]
    PeerIdMismatch,
    #[error("peer_id does not embed an Ed25519 public key (libp2p inline-hash protobuf required)")]
    UnsupportedPeerIdHash,
    #[error("signature failed Ed25519 verification")]
    BadSignature,
    #[error("timestamp {ts} outside acceptable window (now={now})")]
    BadTimestamp { ts: u64, now: u64 },
    #[error("ttl_secs {ttl} exceeds the maximum {max}")]
    BadTtl { ttl: u32, max: u32 },
    #[error("public_url failed format check: {0}")]
    BadUrl(String),
    #[error("version {0:?} is not a valid semver MAJOR.MINOR.PATCH triple")]
    BadVersion(String),
    #[error("per-peer rate limit (1 record/min) exceeded")]
    RateLimited,
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("canonical encoding failed: {0}")]
    Encode(String),
}

/// Validate a `public_url` string per spec 13 §10.3. Accepts:
///   - `https://...`
///   - `http://*.onion/` (any onion virtual host, any port)
///
/// Rejects bare `http://` to non-onion hosts (downgrade poisoning
/// defence — a record claiming `http://example.com` would otherwise be
/// relayed as if it were a legitimate clearnet endpoint).
fn validate_public_url(url: &str) -> Result<(), PresenceError> {
    // Hard cap to bound parser cost.
    if url.len() > 2048 {
        return Err(PresenceError::BadUrl(format!(
            "url length {} exceeds the 2048-byte cap",
            url.len()
        )));
    }
    if let Some(_rest) = url.strip_prefix("https://") {
        // Any non-empty host is acceptable here; we deliberately do NOT
        // do strict URL parsing because the consumer-side probe
        // (spec 13 §10.9) is the source of truth for "does this URL
        // resolve to a working node". Empty host is bogus though.
        if url.len() <= "https://".len() {
            return Err(PresenceError::BadUrl(
                "https:// without a host is not allowed".to_string(),
            ));
        }
        return Ok(());
    }
    if let Some(rest) = url.strip_prefix("http://") {
        // Onion-only. The onion check is structural: the host must
        // end in ".onion" (possibly followed by `:port/` or `/`). We
        // do not enforce v3-only here because incoming records may be
        // forwarded from older nodes; the operator-side denylist is
        // the right surface for filtering deprecated hostnames.
        let host_end = rest
            .find(|c: char| c == '/' || c == ':')
            .unwrap_or(rest.len());
        let host = &rest[..host_end];
        if host.is_empty() {
            return Err(PresenceError::BadUrl(
                "http:// without a host is not allowed".to_string(),
            ));
        }
        if !host.ends_with(".onion") {
            return Err(PresenceError::BadUrl(format!(
                "http:// is only allowed for *.onion hosts, got {host:?}"
            )));
        }
        return Ok(());
    }
    Err(PresenceError::BadUrl(format!(
        "url {:?} must start with https:// or http://*.onion/",
        url
    )))
}

/// Lightweight `MAJOR.MINOR.PATCH` semver check. We hand-roll this
/// rather than pull in the `semver` crate because the validation is
/// purely structural (we never compare versions) and the spec only
/// requires "parses as semver". Optional pre-release / build-metadata
/// suffixes (e.g. `1.2.3-beta`, `1.2.3+build`) are accepted as long as
/// the core triple parses.
fn validate_version(v: &str) -> Result<(), PresenceError> {
    if v.is_empty() || v.len() > 64 {
        return Err(PresenceError::BadVersion(v.to_string()));
    }
    // Strip optional pre-release / build metadata.
    let core_end = v.find(|c: char| c == '-' || c == '+').unwrap_or(v.len());
    let core = &v[..core_end];
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return Err(PresenceError::BadVersion(v.to_string()));
    }
    for p in &parts {
        if p.is_empty() {
            return Err(PresenceError::BadVersion(v.to_string()));
        }
        // Each component must be all-ASCII digits, no leading zero (except literal "0").
        if !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(PresenceError::BadVersion(v.to_string()));
        }
        if p.len() > 1 && p.starts_with('0') {
            return Err(PresenceError::BadVersion(v.to_string()));
        }
        // Bound the value by parsing as u64.
        p.parse::<u64>()
            .map_err(|_| PresenceError::BadVersion(v.to_string()))?;
    }
    Ok(())
}

/// Extract the Ed25519 public key embedded in a libp2p Ed25519 PeerId.
///
/// Ed25519 public-key protobuf encodings are 36 bytes, comfortably
/// below libp2p's 42-byte `MAX_INLINE_KEY_LENGTH`, so EVERY Ed25519
/// PeerId uses the identity multihash (`code = 0`) — the protobuf
/// bytes are embedded directly in the multihash digest. We decode the
/// protobuf and confirm the resulting public key is Ed25519.
///
/// Non-Ed25519 PeerIds (or older RSA-style PeerIds whose protobufs
/// were larger than the inline cap) fail with
/// [`PresenceError::UnsupportedPeerIdHash`]; Ogmara nodes always use
/// Ed25519 keys (see [`crate::node::Node::libp2p_keypair`]) so this
/// only rejects spoofed records that target a non-Ogmara key type.
fn extract_ed25519_public_key(
    peer_id: &PeerId,
) -> Result<libp2p::identity::PublicKey, PresenceError> {
    // `PeerId::as_ref` returns `&multihash::Multihash<64>`. libp2p
    // re-exports its multihash crate via `libp2p_identity::Multihash`
    // — but the simplest path is to call `.code()` / `.digest()`
    // directly through trait-resolution on the reference, since both
    // methods are inherent on the `Multihash<64>` type.
    let mh = peer_id.as_ref();
    // Identity-hash code per libp2p-identity. Anything else means the
    // key was too big to inline (i.e. not Ed25519) and we cannot
    // recover the public key from the PeerId alone.
    if mh.code() != 0 {
        return Err(PresenceError::UnsupportedPeerIdHash);
    }
    let pk = libp2p::identity::PublicKey::try_decode_protobuf(mh.digest())
        .map_err(|e| PresenceError::InvalidPeerId(e.to_string()))?;
    // Defense-in-depth: even though the inline-hash code already
    // implies Ed25519 for valid Ogmara records, confirm explicitly so
    // a future libp2p version that introduces other small-key types
    // doesn't silently degrade validation.
    if pk.clone().try_into_ed25519().is_err() {
        return Err(PresenceError::UnsupportedPeerIdHash);
    }
    Ok(pk)
}

/// Sign a presence-record canonical payload with the local libp2p
/// Ed25519 keypair. Returns the raw signature bytes (64-byte Ed25519
/// signature).
///
/// `record_no_sig` is the canonical signing payload — typically built
/// via [`PresenceRecord::to_signing_payload`] from a freshly-constructed
/// record whose `signature` field is empty.
pub fn sign_record(
    record_no_sig: &PresenceRecordSigned,
    keypair: &libp2p::identity::Keypair,
) -> Result<Vec<u8>, PresenceError> {
    let bytes = rmp_serde::to_vec_named(record_no_sig)
        .map_err(|e| PresenceError::Encode(e.to_string()))?;
    keypair
        .sign(&bytes)
        .map_err(|e| PresenceError::Signing(e.to_string()))
}

/// Verify a presence record's signature against the public key
/// embedded in `record.peer_id`. Re-canonicalizes the record (minus
/// signature) and runs an Ed25519 verification.
///
/// This is the cryptographic check only; full validation (timestamp,
/// TTL, URL format, denylist, rate-limit) lives in
/// [`PresenceManager::validate_record`].
pub fn verify_record(record: &PresenceRecord) -> Result<(), PresenceError> {
    let peer_id: PeerId = record
        .peer_id
        .parse()
        .map_err(|e: libp2p::identity::ParseError| {
            PresenceError::InvalidPeerId(e.to_string())
        })?;
    let pk = extract_ed25519_public_key(&peer_id)?;
    let canon = rmp_serde::to_vec_named(&record.to_signing_payload())
        .map_err(|e| PresenceError::Encode(e.to_string()))?;
    if !pk.verify(&canon, &record.signature) {
        return Err(PresenceError::BadSignature);
    }
    Ok(())
}

/// One row in the in-memory presence cache (spec 13 §10.4).
#[derive(Debug, Clone)]
pub struct CachedPresenceRecord {
    /// The verified record, as it arrived on the wire.
    pub record: PresenceRecord,
    /// When this record was first heard at this node (process-local
    /// monotonic clock).
    pub first_heard: Instant,
    /// When this record was most recently re-received. Updated on
    /// every accepted re-broadcast; drives the cap-eviction order.
    pub last_heard: Instant,
    /// PeerId of the gossip peer that delivered the most recent copy
    /// of this record (diagnostics — useful when tracking down
    /// misbehaving relays).
    pub source_peer: PeerId,
}

/// Bounded in-memory cache of presence records, keyed by libp2p
/// PeerId of the broadcaster. Capped at [`PRESENCE_CACHE_CAP`]; when
/// full, the oldest 10 % by `last_heard` are evicted.
pub struct PresenceCache {
    inner: RwLock<HashMap<PeerId, CachedPresenceRecord>>,
}

impl Default for PresenceCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PresenceCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Return the current number of cached records.
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    /// Return a snapshot of all cached rows. Each entry is a clone —
    /// callers do not hold the lock past the call.
    pub async fn snapshot(&self) -> Vec<CachedPresenceRecord> {
        self.inner.read().await.values().cloned().collect()
    }

    /// Look up a single cached row by PeerId.
    pub async fn get(&self, peer: &PeerId) -> Option<CachedPresenceRecord> {
        self.inner.read().await.get(peer).cloned()
    }

    /// Insert (or refresh) a verified record. Refresh = update
    /// `last_heard` + `source_peer` without resetting `first_heard`.
    /// Returns `true` if a new entry was inserted, `false` for refresh.
    pub async fn upsert(
        &self,
        peer: PeerId,
        record: PresenceRecord,
        source_peer: PeerId,
    ) -> bool {
        let now = Instant::now();
        let mut guard = self.inner.write().await;
        let inserted = match guard.get_mut(&peer) {
            Some(existing) => {
                existing.record = record;
                existing.last_heard = now;
                existing.source_peer = source_peer;
                false
            }
            None => {
                guard.insert(
                    peer,
                    CachedPresenceRecord {
                        record,
                        first_heard: now,
                        last_heard: now,
                        source_peer,
                    },
                );
                true
            }
        };
        if guard.len() > PRESENCE_CACHE_CAP {
            Self::evict_oldest(&mut guard);
        }
        inserted
    }

    /// Drop the oldest 10 % of rows by `last_heard`. Emits a `warn!`
    /// — the cap-eviction path is the Sybil-flood signal.
    fn evict_oldest(map: &mut HashMap<PeerId, CachedPresenceRecord>) {
        let n = map.len();
        // Always evict at least 1; cap at 10 %.
        let to_evict = (n / 10).max(1);
        // Collect (PeerId, last_heard) pairs, partial-sort, drop oldest.
        let mut by_age: Vec<(PeerId, Instant)> = map
            .iter()
            .map(|(p, c)| (*p, c.last_heard))
            .collect();
        // Sort ascending by `last_heard` so the oldest are at the front.
        by_age.sort_by_key(|(_, t)| *t);
        for (peer, _) in by_age.into_iter().take(to_evict) {
            map.remove(&peer);
        }
        warn!(
            evicted = to_evict,
            cap = PRESENCE_CACHE_CAP,
            "presence cache cap reached — evicted oldest 10% by last_heard \
             (Sybil-flood signal or organic high-churn network)"
        );
    }

    /// Sweep TTL-expired entries. Returns the number dropped. Called
    /// periodically by the manager's sweep task.
    pub async fn prune_expired(&self, now_unix: u64) -> usize {
        let mut guard = self.inner.write().await;
        let before = guard.len();
        guard.retain(|_, row| row.record.expires_at() > now_unix);
        before - guard.len()
    }
}

/// Per-PeerId rate limiter for the topic-validation hook. One last-
/// accepted timestamp per PeerId; new records accepted only when the
/// previous timestamp is older than [`PRESENCE_RATE_LIMIT`]. Pruned
/// periodically to bound memory.
pub struct PresenceRateLimiter {
    inner: RwLock<HashMap<PeerId, Instant>>,
}

impl Default for PresenceRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl PresenceRateLimiter {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Non-mutating rate-limit check used as a cheap first-pass gate
    /// BEFORE expensive signature verification (Security Audit W1,
    /// 0.48.0). Returns `true` if a subsequent `check_and_record` for
    /// this peer would succeed under the current state of the map.
    ///
    /// Note that there is a small TOCTOU window between `peek` and
    /// `check_and_record`: two concurrent verifications for the same
    /// peer could both see `peek == true` and both reach
    /// `check_and_record`, where one wins. That's intentional — the
    /// authoritative gate is still `check_and_record` (step 8 of
    /// `validate_record`). `peek` is solely a CPU-burn defence
    /// against attackers who own one valid signing key.
    pub async fn peek(&self, peer: &PeerId) -> bool {
        let guard = self.inner.read().await;
        match guard.get(peer) {
            Some(prev) => Instant::now().duration_since(*prev) >= PRESENCE_RATE_LIMIT,
            None => true,
        }
    }

    /// Atomically: check rate-limit, and on success record the
    /// timestamp. Returns `true` if the request is allowed (and the
    /// limiter has been updated).
    ///
    /// Security Audit W2 (0.48.0): rejects new inserts when the map
    /// exceeds [`PRESENCE_RATE_LIMITER_SOFT_CAP`] entries between
    /// prunes, so a Sybil flood of unique PeerIds can't grow the map
    /// without bound during the 5-min sweep cadence. Existing peers
    /// keep being allowed to refresh their timestamps even at the cap
    /// — the cap only blocks the addition of NEW peers.
    pub async fn check_and_record(&self, peer: &PeerId) -> bool {
        let now = Instant::now();
        let mut guard = self.inner.write().await;
        if let Some(prev) = guard.get(peer) {
            if now.duration_since(*prev) < PRESENCE_RATE_LIMIT {
                return false;
            }
            guard.insert(*peer, now);
            return true;
        }
        // New peer — apply the soft cap.
        if guard.len() >= PRESENCE_RATE_LIMITER_SOFT_CAP {
            return false;
        }
        guard.insert(*peer, now);
        true
    }

    /// Drop entries older than `2 * PRESENCE_RATE_LIMIT` to bound the
    /// map under churn. Called periodically alongside the cache sweep.
    pub async fn prune(&self) {
        let cutoff = Instant::now()
            .checked_sub(PRESENCE_RATE_LIMIT * 2)
            .unwrap_or_else(Instant::now);
        let mut guard = self.inner.write().await;
        guard.retain(|_, t| *t > cutoff);
    }

    /// Current number of tracked peers. Test/diagnostic use only.
    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }
}

/// Outcome of the validation pipeline.
#[derive(Debug)]
pub enum ValidationOutcome {
    /// Record passed every check. Cached + relayed.
    Accepted,
    /// Record failed validation — drop locally, report Reject to
    /// gossipsub so the relay peer's score takes a penalty.
    Rejected(PresenceError),
}

/// Owns the cache, the per-peer rate limiter, the denylist snapshot,
/// and the self-broadcast state. One instance per `NetworkService`.
pub struct PresenceManager {
    /// Network id (used to build the topic string for self-broadcast).
    network_id: String,
    /// Operator-configured denylist of peer IDs (parsed at startup).
    denylist: std::collections::HashSet<PeerId>,
    /// Bounded record cache.
    cache: Arc<PresenceCache>,
    /// Per-peer rate limiter.
    rate_limiter: Arc<PresenceRateLimiter>,
    /// libp2p keypair used to sign our own outbound records.
    keypair: libp2p::identity::Keypair,
    /// Cached base58 PeerId for self-broadcast payloads — avoids
    /// re-encoding on every tick.
    self_peer_id: String,
    /// `[network.presence] record_ttl_secs` snapshot.
    record_ttl_secs: u64,
    /// `[network.presence] rebroadcast_interval_secs` snapshot.
    rebroadcast_interval_secs: u64,
    /// True iff we will publish on the topic (= config enabled AND we
    /// have a non-empty public URL). Drives the broadcasting status
    /// reported on the `/network/identity` endpoint.
    broadcasting: bool,
    /// `[api] public_url` snapshot — `Some` only when we will broadcast.
    public_url: Option<String>,
}

impl PresenceManager {
    /// Construct a new manager from config. Parses the denylist; if
    /// any entry fails to parse, returns an error — but the config
    /// validator already rejects bad denylist entries, so this
    /// double-parse is purely defense-in-depth.
    pub fn new(
        network_id: String,
        config: &crate::config::PresenceConfig,
        keypair: libp2p::identity::Keypair,
        public_url: Option<String>,
    ) -> anyhow::Result<Self> {
        let mut denylist = std::collections::HashSet::new();
        for entry in &config.denylist {
            let pid: PeerId = entry.parse().map_err(|e: libp2p::identity::ParseError| {
                anyhow::anyhow!(
                    "presence denylist entry {:?} did not parse as PeerId: {e}",
                    entry
                )
            })?;
            denylist.insert(pid);
        }
        let self_peer_id = keypair.public().to_peer_id().to_base58();
        // Broadcasting requires BOTH the master switch and a public URL.
        let broadcasting = config.enabled
            && public_url
                .as_ref()
                .map(|u| !u.trim().is_empty())
                .unwrap_or(false);
        if config.enabled && !broadcasting {
            info!(
                "presence-gossip: subscribed but NOT broadcasting — [api] \
                 public_url is empty/unset. Set public_url to advertise this \
                 node on the presence topic."
            );
        }
        Ok(Self {
            network_id,
            denylist,
            cache: Arc::new(PresenceCache::new()),
            rate_limiter: Arc::new(PresenceRateLimiter::new()),
            keypair,
            self_peer_id,
            record_ttl_secs: config.record_ttl_secs,
            rebroadcast_interval_secs: config.rebroadcast_interval_secs,
            broadcasting,
            public_url: if broadcasting { public_url } else { None },
        })
    }

    /// Clone-shareable handle to the cache (for AppState).
    pub fn cache(&self) -> Arc<PresenceCache> {
        self.cache.clone()
    }

    pub fn broadcasting(&self) -> bool {
        self.broadcasting
    }

    pub fn self_peer_id(&self) -> &str {
        &self.self_peer_id
    }

    pub fn public_url(&self) -> Option<&str> {
        self.public_url.as_deref()
    }

    pub fn record_ttl_secs(&self) -> u64 {
        self.record_ttl_secs
    }

    pub fn rebroadcast_interval_secs(&self) -> u64 {
        self.rebroadcast_interval_secs
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Validate a record per spec 13 §10.3 plus the per-peer rate limit
    /// (spec 13 §10.9). Used by the gossipsub message handler. The
    /// `originating_peer` is the libp2p PeerId that delivered the
    /// gossipsub message to us (`propagation_source`); for newly-
    /// authored records this equals `record.peer_id`, but a relay step
    /// can change it — the signature check is the authoritative
    /// "is this record really from `record.peer_id`" test.
    ///
    /// **Cost ordering (Security Audit W1, v0.48.0):** cheap checks
    /// run first; expensive Ed25519 signature verify only runs after a
    /// non-mutating rate-limit `peek` has confirmed the peer is within
    /// budget. The authoritative `check_and_record` runs last as
    /// before, so two concurrent requests from the same peer can both
    /// pass `peek` and still have exactly one win at `check_and_record`.
    pub async fn validate_record(
        &self,
        bytes: &[u8],
    ) -> Result<PresenceRecord, PresenceError> {
        // 0. Envelope size guard (Security Audit W4) — reject before
        //    msgpack decode so an attacker cannot force a 256 KB
        //    deserialize + downstream sig verify with garbage padding.
        if bytes.len() > PRESENCE_MAX_ENVELOPE_BYTES {
            return Err(PresenceError::EnvelopeTooLarge(
                bytes.len(),
                PRESENCE_MAX_ENVELOPE_BYTES,
            ));
        }

        // 1. Decode.
        let record: PresenceRecord = rmp_serde::from_slice(bytes)
            .map_err(|e| PresenceError::Decode(e.to_string()))?;

        // 2. peer_id parse + denylist.
        let claimed_peer_id: PeerId = record
            .peer_id
            .parse()
            .map_err(|e: libp2p::identity::ParseError| {
                PresenceError::InvalidPeerId(e.to_string())
            })?;
        if self.denylist.contains(&claimed_peer_id) {
            return Err(PresenceError::Denylisted);
        }

        // 3. Rate-limit PEEK — cheap, non-mutating. Stops an attacker
        //    with one valid signing key from burning CPU at sig-verify
        //    rate (Security Audit W1).
        if !self.rate_limiter.peek(&claimed_peer_id).await {
            return Err(PresenceError::RateLimited);
        }

        // 4. TTL ceiling (spec 13 §10.3: ≤ 7 days).
        if record.ttl_secs > PRESENCE_MAX_TTL_SECS {
            return Err(PresenceError::BadTtl {
                ttl: record.ttl_secs,
                max: PRESENCE_MAX_TTL_SECS,
            });
        }

        // 5. Timestamp window.
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let earliest = now_unix.saturating_sub(PRESENCE_PAST_SKEW_SECS);
        let latest = now_unix.saturating_add(PRESENCE_FUTURE_SKEW_SECS);
        if record.timestamp <= earliest || record.timestamp >= latest {
            return Err(PresenceError::BadTimestamp {
                ts: record.timestamp,
                now: now_unix,
            });
        }

        // 6. Version semver.
        validate_version(&record.version)?;

        // 7. public_url format (only when present).
        if let Some(ref url) = record.public_url {
            validate_public_url(url)?;
        }

        // 8. Signature (expensive — ~50µs Ed25519 verify).
        verify_record(&record)?;

        // 9. Per-peer rate-limit AUTHORITATIVE check + record. After
        //    sig verify so the record is provably from this peer
        //    before we burn one of its 1-record/min budget.
        if !self.rate_limiter.check_and_record(&claimed_peer_id).await {
            return Err(PresenceError::RateLimited);
        }

        Ok(record)
    }

    /// Process an incoming gossipsub message that arrived on the
    /// presence topic: validate, and on success insert into the cache.
    /// Returns the [`ValidationOutcome`] so the caller (the network
    /// event loop) can call
    /// `gossipsub.report_message_validation_result(...)` with the
    /// matching `MessageAcceptance` variant.
    pub async fn handle_gossip_message(
        &self,
        propagation_source: PeerId,
        bytes: &[u8],
    ) -> ValidationOutcome {
        match self.validate_record(bytes).await {
            Ok(record) => {
                // Record's PeerId was validated to parse cleanly + denylist
                // + signature inside `validate_record`. Parse again here
                // because `validate_record` returns the decoded record but
                // not the parsed PeerId; the cost is one base58 decode.
                let key: PeerId = match record.peer_id.parse() {
                    Ok(p) => p,
                    Err(e) => {
                        return ValidationOutcome::Rejected(
                            PresenceError::InvalidPeerId(e.to_string()),
                        );
                    }
                };
                let inserted = self
                    .cache
                    .upsert(key, record, propagation_source)
                    .await;
                if inserted {
                    debug!(peer = %key, "presence cache: new record");
                } else {
                    debug!(peer = %key, "presence cache: record refreshed");
                }
                ValidationOutcome::Accepted
            }
            Err(e) => {
                debug!(error = %e, "presence record rejected");
                ValidationOutcome::Rejected(e)
            }
        }
    }

    /// Build and sign the self-broadcast record. Returns the wire
    /// bytes ready to publish on the gossipsub topic.
    pub fn build_self_record(&self) -> Result<Vec<u8>, PresenceError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let signing = PresenceRecordSigned {
            peer_id: self.self_peer_id.clone(),
            public_url: self.public_url.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: now,
            ttl_secs: self.record_ttl_secs as u32,
        };
        let signature = sign_record(&signing, &self.keypair)?;
        let record = PresenceRecord {
            peer_id: signing.peer_id,
            public_url: signing.public_url,
            version: signing.version,
            timestamp: signing.timestamp,
            ttl_secs: signing.ttl_secs,
            signature,
        };
        rmp_serde::to_vec_named(&record).map_err(|e| PresenceError::Encode(e.to_string()))
    }

    /// Run the periodic TTL sweep + rate-limiter pruning. Should be
    /// spawned as a tokio task and run until shutdown.
    pub async fn run_sweep(
        self: Arc<Self>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        let mut interval = tokio::time::interval(PRESENCE_SWEEP_INTERVAL);
        // Skip the immediate first tick — nothing to sweep at startup.
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now_unix = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let dropped = self.cache.prune_expired(now_unix).await;
                    self.rate_limiter.prune().await;
                    if dropped > 0 {
                        debug!(dropped, "presence cache: TTL sweep");
                    }
                }
                _ = shutdown_rx.recv() => {
                    debug!("presence-sweep shutting down");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn build_signed_record(
        keypair: &Keypair,
        public_url: Option<String>,
        ttl_secs: u32,
        ts_offset: i64,
    ) -> PresenceRecord {
        let peer_id = keypair.public().to_peer_id().to_base58();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let signing = PresenceRecordSigned {
            peer_id: peer_id.clone(),
            public_url: public_url.clone(),
            version: "0.48.0".to_string(),
            timestamp: (now + ts_offset).max(0) as u64,
            ttl_secs,
        };
        let signature = sign_record(&signing, keypair).expect("sign");
        PresenceRecord {
            peer_id,
            public_url,
            version: signing.version,
            timestamp: signing.timestamp,
            ttl_secs,
            signature,
        }
    }

    fn empty_presence_config() -> crate::config::PresenceConfig {
        crate::config::PresenceConfig::default()
    }

    #[tokio::test]
    async fn round_trip_signed_record_verifies() {
        let kp = Keypair::generate_ed25519();
        let rec = build_signed_record(
            &kp,
            Some("https://node.example.org".to_string()),
            86_400,
            0,
        );
        // Sign / verify round-trip.
        verify_record(&rec).expect("must verify");
        // Wire round-trip.
        let bytes = rmp_serde::to_vec_named(&rec).expect("encode");
        let rec2: PresenceRecord = rmp_serde::from_slice(&bytes).expect("decode");
        verify_record(&rec2).expect("decoded must verify");
        assert_eq!(rec.peer_id, rec2.peer_id);
    }

    #[tokio::test]
    async fn validate_accepts_clean_record() {
        let kp = Keypair::generate_ed25519();
        let rec = build_signed_record(
            &kp,
            Some("https://node.example.org".to_string()),
            86_400,
            0,
        );
        let mgr = Arc::new(
            PresenceManager::new(
                "testnet".to_string(),
                &empty_presence_config(),
                Keypair::generate_ed25519(),
                None,
            )
            .expect("mgr"),
        );
        let bytes = rmp_serde::to_vec_named(&rec).expect("encode");
        let out = mgr.validate_record(&bytes).await;
        assert!(out.is_ok(), "clean record must accept: {out:?}");
    }

    #[tokio::test]
    async fn bad_signature_rejected() {
        let kp = Keypair::generate_ed25519();
        let mut rec = build_signed_record(&kp, None, 86_400, 0);
        // Flip a byte in the signature.
        rec.signature[0] ^= 0xff;
        let err = verify_record(&rec).expect_err("tampered sig must fail");
        assert!(matches!(err, PresenceError::BadSignature));
    }

    #[tokio::test]
    async fn bad_timestamp_rejected_past() {
        let kp = Keypair::generate_ed25519();
        // 2h in the past — outside the 1h past-skew window.
        let rec = build_signed_record(&kp, None, 86_400, -7200);
        let mgr = Arc::new(
            PresenceManager::new(
                "testnet".to_string(),
                &empty_presence_config(),
                Keypair::generate_ed25519(),
                None,
            )
            .expect("mgr"),
        );
        let bytes = rmp_serde::to_vec_named(&rec).expect("encode");
        let err = mgr
            .validate_record(&bytes)
            .await
            .expect_err("past timestamp must reject");
        assert!(matches!(err, PresenceError::BadTimestamp { .. }));
    }

    #[tokio::test]
    async fn bad_url_http_non_onion_rejected() {
        let kp = Keypair::generate_ed25519();
        let rec = build_signed_record(
            &kp,
            Some("http://example.com".to_string()),
            86_400,
            0,
        );
        let mgr = Arc::new(
            PresenceManager::new(
                "testnet".to_string(),
                &empty_presence_config(),
                Keypair::generate_ed25519(),
                None,
            )
            .expect("mgr"),
        );
        let bytes = rmp_serde::to_vec_named(&rec).expect("encode");
        let err = mgr
            .validate_record(&bytes)
            .await
            .expect_err("http:// non-onion must reject");
        assert!(matches!(err, PresenceError::BadUrl(_)));
    }

    #[tokio::test]
    async fn onion_url_accepted() {
        let kp = Keypair::generate_ed25519();
        let onion_host = format!("{}.onion", "a".repeat(56));
        let url = format!("http://{onion_host}/");
        let rec = build_signed_record(&kp, Some(url), 86_400, 0);
        let mgr = Arc::new(
            PresenceManager::new(
                "testnet".to_string(),
                &empty_presence_config(),
                Keypair::generate_ed25519(),
                None,
            )
            .expect("mgr"),
        );
        let bytes = rmp_serde::to_vec_named(&rec).expect("encode");
        mgr.validate_record(&bytes).await.expect("onion must accept");
    }

    #[tokio::test]
    async fn ttl_over_cap_rejected() {
        let kp = Keypair::generate_ed25519();
        // 8 days = beyond the 7d cap.
        let rec = build_signed_record(&kp, None, 8 * 24 * 3600, 0);
        let mgr = Arc::new(
            PresenceManager::new(
                "testnet".to_string(),
                &empty_presence_config(),
                Keypair::generate_ed25519(),
                None,
            )
            .expect("mgr"),
        );
        let bytes = rmp_serde::to_vec_named(&rec).expect("encode");
        let err = mgr
            .validate_record(&bytes)
            .await
            .expect_err("oversize TTL must reject");
        assert!(matches!(err, PresenceError::BadTtl { .. }));
    }

    #[tokio::test]
    async fn denylist_match_rejected() {
        let kp = Keypair::generate_ed25519();
        let rec = build_signed_record(&kp, None, 86_400, 0);
        let mut cfg = empty_presence_config();
        cfg.denylist = vec![rec.peer_id.clone()];
        let mgr = Arc::new(
            PresenceManager::new(
                "testnet".to_string(),
                &cfg,
                Keypair::generate_ed25519(),
                None,
            )
            .expect("mgr"),
        );
        let bytes = rmp_serde::to_vec_named(&rec).expect("encode");
        let err = mgr
            .validate_record(&bytes)
            .await
            .expect_err("denylisted peer must reject");
        assert!(matches!(err, PresenceError::Denylisted));
    }

    #[tokio::test]
    async fn rate_limit_two_records_back_to_back() {
        let kp = Keypair::generate_ed25519();
        let rec1 = build_signed_record(&kp, None, 86_400, 0);
        let rec2 = build_signed_record(&kp, None, 86_400, 1);
        let mgr = Arc::new(
            PresenceManager::new(
                "testnet".to_string(),
                &empty_presence_config(),
                Keypair::generate_ed25519(),
                None,
            )
            .expect("mgr"),
        );
        let b1 = rmp_serde::to_vec_named(&rec1).expect("encode1");
        let b2 = rmp_serde::to_vec_named(&rec2).expect("encode2");
        mgr.validate_record(&b1).await.expect("first ok");
        let err = mgr
            .validate_record(&b2)
            .await
            .expect_err("second within 60s must fail");
        assert!(matches!(err, PresenceError::RateLimited));
    }

    #[tokio::test]
    async fn cache_cap_eviction() {
        let cache = Arc::new(PresenceCache::new());
        // Insert 1 over the cap; the most recent insert triggers the
        // 10% eviction path.
        for i in 0..(PRESENCE_CACHE_CAP + 1) {
            let kp = Keypair::generate_ed25519();
            let rec = build_signed_record(&kp, None, 86_400, 0);
            let peer: PeerId = rec.peer_id.parse().unwrap();
            cache.upsert(peer, rec, peer).await;
            // Tiny sleep so `last_heard` ordering is deterministic
            // (Instant resolution can collapse otherwise on fast CI).
            if i < 10 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        let len = cache.len().await;
        assert!(
            len <= PRESENCE_CACHE_CAP,
            "cache must stay within cap after eviction, got {len}"
        );
    }

    #[tokio::test]
    async fn ttl_prune_drops_expired() {
        let cache = Arc::new(PresenceCache::new());
        let kp = Keypair::generate_ed25519();
        // Build an "expired" record: timestamp 1000s ago, ttl 100s.
        // (We don't run it through validate — just through the cache,
        // which is the layer responsible for TTL pruning.)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let signing = PresenceRecordSigned {
            peer_id: kp.public().to_peer_id().to_base58(),
            public_url: None,
            version: "0.48.0".to_string(),
            timestamp: now.saturating_sub(1000),
            ttl_secs: 100,
        };
        let signature = sign_record(&signing, &kp).expect("sign");
        let rec = PresenceRecord {
            peer_id: signing.peer_id.clone(),
            public_url: None,
            version: signing.version,
            timestamp: signing.timestamp,
            ttl_secs: signing.ttl_secs,
            signature,
        };
        let peer: PeerId = rec.peer_id.parse().unwrap();
        cache.upsert(peer, rec, peer).await;
        assert_eq!(cache.len().await, 1);
        let dropped = cache.prune_expired(now).await;
        assert_eq!(dropped, 1);
        assert_eq!(cache.len().await, 0);
    }

    #[test]
    fn semver_parser_accepts_canonical() {
        validate_version("0.48.0").unwrap();
        validate_version("1.2.3").unwrap();
        validate_version("10.20.30").unwrap();
        validate_version("0.48.0-beta.1").unwrap();
        validate_version("0.48.0+build42").unwrap();
    }

    #[test]
    fn semver_parser_rejects_bad() {
        assert!(validate_version("").is_err());
        assert!(validate_version("0.48").is_err());
        assert!(validate_version("v0.48.0").is_err());
        assert!(validate_version("0.48.x").is_err());
        // Leading zeros in non-zero components are rejected
        // (canonical semver).
        assert!(validate_version("01.0.0").is_err());
    }

    /// Security Audit W4 (v0.48.0): envelope-size guard rejects
    /// payloads above [`PRESENCE_MAX_ENVELOPE_BYTES`] BEFORE attempting
    /// the (relatively expensive) msgpack decode + signature verify.
    /// Defends against attackers padding 256 KB of valid msgpack
    /// garbage to burn CPU.
    #[tokio::test]
    async fn envelope_too_large_rejected_before_decode() {
        let mgr = Arc::new(
            PresenceManager::new(
                "testnet".to_string(),
                &empty_presence_config(),
                Keypair::generate_ed25519(),
                None,
            )
            .expect("mgr"),
        );
        // Even though this is well-formed msgpack of a real record,
        // the size guard rejects it before sig verify.
        let kp = Keypair::generate_ed25519();
        let rec = build_signed_record(&kp, None, 86_400, 0);
        let mut bytes = rmp_serde::to_vec_named(&rec).expect("encode");
        // Pad to just above the cap. Note: we never feed this to the
        // decoder, so we don't need it to remain valid msgpack.
        bytes.resize(PRESENCE_MAX_ENVELOPE_BYTES + 1, 0);
        let out = mgr.validate_record(&bytes).await;
        match out {
            Err(PresenceError::EnvelopeTooLarge(got, cap)) => {
                assert_eq!(got, PRESENCE_MAX_ENVELOPE_BYTES + 1);
                assert_eq!(cap, PRESENCE_MAX_ENVELOPE_BYTES);
            }
            other => panic!("expected EnvelopeTooLarge, got {other:?}"),
        }
    }

    /// Security Audit W2 (v0.48.0): once the rate-limiter map has
    /// [`PRESENCE_RATE_LIMITER_SOFT_CAP`] entries, new PeerIds are
    /// refused even if their per-peer budget would otherwise allow.
    /// Existing peers can still refresh as long as their 1-min window
    /// has elapsed.
    #[tokio::test]
    async fn rate_limiter_soft_cap_blocks_new_peers() {
        let limiter = PresenceRateLimiter::new();
        // Saturate the map at exactly the soft cap.
        for _ in 0..PRESENCE_RATE_LIMITER_SOFT_CAP {
            let kp = Keypair::generate_ed25519();
            let pid = kp.public().to_peer_id();
            assert!(limiter.check_and_record(&pid).await, "fill");
        }
        assert_eq!(limiter.len().await, PRESENCE_RATE_LIMITER_SOFT_CAP);
        // One more NEW peer must be refused.
        let kp_new = Keypair::generate_ed25519();
        let pid_new = kp_new.public().to_peer_id();
        assert!(!limiter.check_and_record(&pid_new).await);
        assert_eq!(
            limiter.len().await,
            PRESENCE_RATE_LIMITER_SOFT_CAP,
            "soft cap must not grow on refusal"
        );
    }

    /// X3 (v0.48.0): a record that fails validation reaches the
    /// gossipsub-handler boundary as
    /// [`ValidationOutcome::Rejected`], which the swarm event loop
    /// in `network::mod` translates to
    /// `libp2p::gossipsub::MessageAcceptance::Reject` — that
    /// instructs libp2p to suppress mesh relay. This test exercises
    /// the PresenceManager half of the chain (the swarm half is
    /// straight code inspection of `handle_presence_message` in
    /// `mod.rs`). A failure here means rejected records would still
    /// be cached locally, breaking spec 13 §10.3.
    #[tokio::test]
    async fn rejected_record_yields_reject_outcome() {
        let mgr = Arc::new(
            PresenceManager::new(
                "testnet".to_string(),
                &empty_presence_config(),
                Keypair::generate_ed25519(),
                None,
            )
            .expect("mgr"),
        );
        let kp = Keypair::generate_ed25519();
        // Tampered signature.
        let mut rec = build_signed_record(
            &kp,
            Some("https://node.example.org".to_string()),
            86_400,
            0,
        );
        rec.signature[0] ^= 0xff;
        let bytes = rmp_serde::to_vec_named(&rec).expect("encode");
        let outcome = mgr
            .handle_gossip_message(kp.public().to_peer_id(), &bytes)
            .await;
        match outcome {
            ValidationOutcome::Rejected(_) => {}
            ValidationOutcome::Accepted => {
                panic!("tampered record must be rejected, not accepted")
            }
        }
        // And the record must not have entered the cache.
        let cached = mgr
            .cache()
            .get(&kp.public().to_peer_id())
            .await;
        assert!(
            cached.is_none(),
            "rejected record must not be in local cache"
        );
    }
}
