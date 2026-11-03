//! Node-side key-epoch arbitration for channel-scope `ChannelKeyEnvelope`s
//! (l2-node 0.143.0, protocol §8.1.2).
//!
//! Before 0.143.0 every `(scope, target, device, epoch)` row in
//! `CHANNEL_KEYS` was first-write-wins **per device**: two members that
//! established the same epoch concurrently each won some devices, and the
//! channel was permanently forked for that epoch (different members held
//! different keys). Client-side ordering cannot fix a per-device FWW.
//!
//! The node now records, per channel `(scope, epoch)`, ONE winning
//! `key_commitment` (`CHANNEL_KEY_COMMITS`). Every channel-scope envelope
//! carries the full rank `(key_ts, key_commitment)`; the LOWEST rank wins:
//!
//! A candidate key is identified by the PAIR `(key_ts, key_commitment)`
//! (the commitment itself binds `key_ts`: `keccak256("ogmara-chankey-
//! commit-v1" || scope || epoch_be8 || key_ts_be8 || key)`):
//!
//! * freshness (content-only, uniform): an envelope whose
//!   `timestamp - key_ts` exceeds `KEY_TS_MAX_AGE_MS` is refused
//!   (`key_ts_stale`) UNLESS its pair is exactly the current winner (late
//!   wraps of an established key may join);
//! * no state + pair             → record `arbitrated(pair)`, store the wrap;
//! * same pair as the winner     → store the wrap (another target, same key);
//!   every `(target, device, epoch)` slot is write-once (first write wins);
//! * different pair              → SUPERSEDE only when it ranks strictly
//!   better AND the epoch is still inside the finality horizon
//!   (`recorded_at + KEY_FINALITY_MS`, `recorded_at` = when THIS node first
//!   arbitrated the epoch — superseding never extends it); every row at that
//!   epoch whose `(key_commitment, key_ts)` differs is deleted in the same
//!   batch. Otherwise → conflict (409). Nothing else influences the winner.
//! * `legacy` (rows that predate arbitration) → plain first-write-wins,
//!   nothing recorded; a commitment-less envelope is accepted ONLY here.
//!
//! Because the decision depends only on envelope content plus the recorded
//! winner, every node converges on the same winner regardless of gossip
//! order, as long as all competing envelopes reach it within the finality
//! horizon. Residuals (documented in the CHANGELOG): a gossip partition of
//! ANY length during a concurrent rotation splits that epoch until the next
//! rotation when the establishing envelopes are dropped and not re-delivered
//! live inside `KEY_FINALITY_MS` (no sync path carries key envelopes); and because `recorded_at` is per node
//! (local wall clock, first arrival), an envelope arriving right at the
//! 120 s boundary — or on a node whose clock jumped — can be accepted on one
//! node and refused on another. Clients discard a pending key older than
//! `finality / 2` before its first publish to stay clear of that boundary.
//! A fresh or late node has the same issue in a sharper form: its
//! `recorded_at` is when IT first saw the epoch, possibly long after the
//! rest of the mesh finalized, so a better pair it receives later can still
//! supersede there while being refused everywhere else.
//!
//! Further rules:
//! * sync/backfill ingestion (no drift check, no rate limit) only adds
//!   wraps of the ALREADY recorded winner (`key_sync_not_winner`
//!   otherwise). No sync protocol currently carries key envelopes at all, so
//!   a key split by a gossip partition is NOT healed by the node: members on
//!   the two sides can keep different keys for that epoch until the next
//!   rotation (client-side split detection / rotation; a real key-envelope
//!   backfill would be a separate future design);
//! * a NEW epoch may sit at most `CHANNEL_KEY_EPOCH_MAX_AHEAD` (256) above
//!   `max(highest known epoch, private floor)` (`key_epoch_too_far`) — a
//!   wide sanity bound only; full scopes evict the lowest epoch first, and
//!   the 512-row commit cap evicts the lowest epoch and raises the eviction
//!   horizon past it (no epoch is protected — see the CHANGELOG residuals);
//! * the hot path never copies row values except on a supersede; legacy
//!   detection and the cap check are keys-only and are skipped entirely
//!   once the migration's Phase A ran.
//!
//! The whole read-decide-write runs under `channel_key_envelope_lock` and
//! commits as ONE `WriteBatch`: commit row + supersede/eviction deletions +
//! the `CHANNEL_KEYS` put + the `MESSAGES` put + the `TOTAL_MESSAGES` merge
//! (the router skips its generic Step 8 store for these envelopes).

use std::collections::HashSet;

use anyhow::{Context, Result};
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::rocks::Storage;
use super::schema::{self, cf, state_keys};

/// Finality horizon: a better-ranked commitment can supersede the recorded
/// winner only while `now < recorded_at + KEY_FINALITY_MS`.
pub const KEY_FINALITY_MS: u64 = 120_000;

/// Max `envelope.timestamp - key_ts` for a pair that is NOT the current
/// winner (create and supersede alike → `key_ts_stale`). Why content-only
/// and uniform: a rule that depended on local state (e.g. only checked on
/// supersede) let one node record a back-dated pair as the first winner
/// while another refused it as a superseder → a cross-node fork (audit B1).
/// Late wraps of the CURRENT winner are exempt so members who join hours
/// later can still be covered with the established key.
pub const KEY_TS_MAX_AGE_MS: u64 = 15 * 60_000;

/// Max `CHANNEL_KEY_COMMITS` epoch rows retained per scope. When a NEW epoch
/// row would exceed it, the lowest epoch row is evicted and every epoch at or
/// below it is refused from then on (`evicted_below` in the scope meta row),
/// so an evicted epoch can never silently fall back to first-write-wins.
pub const MAX_KEY_COMMITS_PER_SCOPE: usize = 512;

/// How far a NEW epoch may sit above `max(highest known epoch, private
/// floor)` (`key_epoch_too_far` beyond it). Deliberately WIDE — the pre-0.143
/// value (P2d C1: it only has to stop near-`u64::MAX` epochs that would
/// saturate the rotation floor). A tight bound (+2 was tried in round 2) is
/// built on NODE-LOCAL inputs: key envelopes are never backfilled, so a node
/// that federated a channel late or missed a few rotations has a low local
/// maximum and would refuse every honest rotation forever (round-3 audit
/// B2). It also did not stop pre-squatting: a member can ratchet one epoch
/// at a time. Pre-squatting / ratcheting is a documented residual; recovery
/// is kick (raises the floor) + rotate.
pub const CHANNEL_KEY_EPOCH_MAX_AHEAD: u64 = 256;

/// Max superseded-commitment entries kept on a commit row (newest kept).
pub const MAX_SUPERSEDED_HISTORY: usize = 4;

/// Commit-row state: a winning commitment is recorded.
pub const STATE_ARBITRATED: &str = "arbitrated";
/// Commit-row state: the epoch's rows predate arbitration (first-write-wins).
pub const STATE_LEGACY: &str = "legacy";
/// Reported (never stored) when nothing is known for an epoch.
pub const STATE_NONE: &str = "none";

/// MESSAGES rows scanned between two persisted resume cursors in the
/// migration's `msg_id` back-fill phase.
const MIGRATION_CURSOR_EVERY: usize = 10_000;

/// One superseded commitment kept for traceability on a commit row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SupersededEntry {
    /// Hex of the superseded `key_commitment`.
    pub c: String,
    /// The superseded pair's `key_ts`.
    #[serde(default)]
    pub key_ts: Option<u64>,
    /// Wallet that had established the superseded key (if known).
    #[serde(default)]
    pub author: Option<String>,
    /// Node-clock ms at which it was superseded.
    pub at: u64,
}

/// The `CHANNEL_KEY_COMMITS` row for one `(scope, epoch)`. Single owner
/// (this module), so a typed round-trip is safe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyCommitRecord {
    /// Hex of the winning `key_commitment` (`None` for `legacy`).
    #[serde(default)]
    pub c: Option<String>,
    /// The winner's `key_ts` (`None` for `legacy`).
    #[serde(default)]
    pub key_ts: Option<u64>,
    /// Wallet whose envelope established the winner.
    #[serde(default)]
    pub author: Option<String>,
    /// Hex msg_id of the envelope that established the winner.
    #[serde(default)]
    pub msg_id: Option<String>,
    /// Node-clock ms when this node first recorded the epoch (finality anchor).
    pub recorded_at: u64,
    /// `"arbitrated"` or `"legacy"`.
    pub state: String,
    /// Up to `MAX_SUPERSEDED_HISTORY` superseded commitments (newest last).
    #[serde(default)]
    pub superseded: Vec<SupersededEntry>,
}

impl KeyCommitRecord {
    fn legacy(now_ms: u64) -> Self {
        Self {
            c: None,
            key_ts: None,
            author: None,
            msg_id: None,
            recorded_at: now_ms,
            state: STATE_LEGACY.to_string(),
            superseded: Vec::new(),
        }
    }

    /// The winning commitment, when this row is a well-formed arbitrated row.
    fn winner(&self) -> Option<([u8; 32], u64)> {
        if self.state != STATE_ARBITRATED {
            return None;
        }
        Some((decode32(self.c.as_deref()?)?, self.key_ts?))
    }

    /// Whether the epoch is past the finality horizon at `now_ms`.
    pub fn is_final(&self, now_ms: u64) -> bool {
        now_ms >= self.recorded_at.saturating_add(KEY_FINALITY_MS)
    }
}

/// Per-scope meta row of `CHANNEL_KEY_COMMITS` (bare 32-byte scope key).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ScopeMeta {
    /// Every epoch strictly below this was evicted by the per-scope cap.
    #[serde(default)]
    evicted_below: u64,
}

fn decode32(h: &str) -> Option<[u8; 32]> {
    let v = hex::decode(h).ok()?;
    v.try_into().ok()
}

fn epoch_of_key(k: &[u8]) -> u64 {
    if k.len() >= 8 {
        u64::from_be_bytes(k[k.len() - 8..].try_into().unwrap_or([0; 8]))
    } else {
        0
    }
}

/// Everything Step 7h needs to arbitrate and store one channel-scope
/// `ChannelKeyEnvelope`.
pub struct ChannelKeyArbInput<'a> {
    /// Derived channel scope (already verified against `channel_id`).
    pub key_scope: [u8; 32],
    /// Channel id (for the private-channel `key_epoch_floor` check).
    pub channel_id: u64,
    /// Envelope epoch.
    pub epoch: u64,
    /// Recipient wallet.
    pub target: &'a str,
    /// Recipient device id (hex).
    pub device_id_hex: &'a str,
    /// Resolved (wallet) author of the envelope.
    pub author: &'a str,
    /// Payload `key_commitment`.
    pub key_commitment: Option<[u8; 32]>,
    /// Payload `key_ts`.
    pub key_ts: Option<u64>,
    /// Signed envelope timestamp.
    pub envelope_ts: u64,
    /// Envelope msg_id.
    pub msg_id: [u8; 32],
    /// Serialized `CHANNEL_KEYS` record (JSON) to store on success.
    pub record: &'a [u8],
    /// Raw envelope bytes (stored into `MESSAGES` in the same batch).
    pub raw_envelope: &'a [u8],
    /// Node clock (ms).
    pub now_ms: u64,
    /// `CHANNEL_KEYS` per-scope row cap.
    pub scope_cap: usize,
    /// Arrived via a sync/backfill path (no drift check, no rate limit):
    /// then only wraps of the already recorded winner are accepted.
    pub sync: bool,
}

/// The recorded winner reported with a conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCommitWinner {
    /// Winning commitment.
    pub key_commitment: [u8; 32],
    /// Winning `key_ts`.
    pub key_ts: u64,
    /// Wallet that established it.
    pub author: Option<String>,
    /// Envelope that established it.
    pub msg_id: Option<[u8; 32]>,
    /// Whether the epoch is past the finality horizon.
    pub is_final: bool,
}

/// Why Step 7h refused an envelope without a conflict (all 400s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyArbRejection {
    /// A non-legacy epoch requires `key_commitment` + `key_ts`.
    CommitmentRequired,
    /// `envelope.timestamp - key_ts > KEY_TS_MAX_AGE_MS` and the pair is not
    /// the current winner.
    KeyTsStale,
    /// Private channel: epoch below `key_epoch_floor`.
    EpochBelowFloor {
        /// The channel's current floor.
        floor: u64,
    },
    /// Epoch at/below the per-scope eviction horizon.
    EpochEvicted {
        /// Lowest epoch still accepted.
        below: u64,
    },
    /// `CHANNEL_KEYS` scope full and nothing lower-epoch to evict.
    ScopeFull,
    /// Sync/backfill ingestion carried a pair that is neither the recorded
    /// winner nor a fresh (by this node's clock) supersede candidate.
    SyncNotWinner,
    /// A new epoch more than `CHANNEL_KEY_EPOCH_MAX_AHEAD` above
    /// `max(highest known epoch, floor)`.
    EpochTooFarAhead {
        /// Highest epoch currently accepted as new.
        bound: u64,
    },
}

impl KeyArbRejection {
    /// Stable machine-readable code (returned to HTTP clients).
    pub fn code(&self) -> &'static str {
        match self {
            Self::CommitmentRequired => "key_commitment_required",
            Self::KeyTsStale => "key_ts_stale",
            Self::EpochBelowFloor { .. } => "key_epoch_below_floor",
            Self::EpochEvicted { .. } => "key_epoch_evicted",
            Self::ScopeFull => "key_scope_full",
            Self::SyncNotWinner => "key_sync_not_winner",
            Self::EpochTooFarAhead { .. } => "key_epoch_too_far",
        }
    }
}

/// Outcome of [`Storage::arbitrate_and_store_channel_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelKeyArbOutcome {
    /// The wrap was stored (and the envelope persisted).
    Stored,
    /// A wrap for this `(target, device, epoch)` already existed (kept). The
    /// envelope is NOT persisted (and must not be relayed).
    AlreadyPresent,
    /// Losing rank, or a better rank after finality — nothing written.
    Conflict(KeyCommitWinner),
    /// Refused — nothing written.
    Rejected(KeyArbRejection),
}

/// Read view of one epoch's arbitration state (GET key-commitment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCommitView {
    /// `"none"`, `"legacy"` or `"arbitrated"`.
    pub state: &'static str,
    /// The stored row, when one exists.
    pub record: Option<KeyCommitRecord>,
}

enum EpochState {
    None,
    /// `true` when the legacy row must be written now (lazy detection).
    Legacy(bool),
    Arbitrated(KeyCommitRecord, [u8; 32], u64),
}

impl Storage {
    /// `key_epoch_floor` of a PRIVATE channel (`channel_type == 2`), else 0.
    fn private_key_epoch_floor(&self, channel_id: u64) -> Result<u64> {
        let Some(bytes) = self.get_cf(cf::CHANNELS, &channel_id.to_be_bytes())? else {
            return Ok(0);
        };
        let meta: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(m) => m,
            Err(_) => return Ok(0),
        };
        if meta.get("channel_type").and_then(|v| v.as_u64()) != Some(2) {
            return Ok(0);
        }
        Ok(meta.get("key_epoch_floor").and_then(|v| v.as_u64()).unwrap_or(0))
    }

    /// The per-scope meta row. A row that does not parse FAILS CLOSED: a
    /// lossy default would read `evicted_below = 0` and silently re-open
    /// every evicted epoch to a fresh arbitration (round-2 audit N3).
    fn key_commit_scope_meta(&self, scope: &[u8; 32]) -> Result<ScopeMeta> {
        let key = schema::encode_key_commit_scope_meta_key(scope);
        Ok(match self.get_cf(cf::CHANNEL_KEY_COMMITS, &key)? {
            Some(b) => serde_json::from_slice(&b).context("corrupt channel_key_commits scope meta row")?,
            None => ScopeMeta::default(),
        })
    }

    /// Read the `CHANNEL_KEY_COMMITS` row for `(scope, epoch)`. A row that no
    /// longer parses is an error (fail closed — never silently "none").
    pub fn get_key_commit(&self, scope: &[u8; 32], epoch: u64) -> Result<Option<KeyCommitRecord>> {
        let key = schema::encode_key_commit_key(scope, epoch);
        match self.get_cf(cf::CHANNEL_KEY_COMMITS, &key)? {
            Some(b) => Ok(Some(
                serde_json::from_slice(&b).context("corrupt channel_key_commits row")?,
            )),
            None => Ok(None),
        }
    }

    /// KEYS-ONLY scan of `cf_name` under `prefix` (≤ `limit` keys). Never
    /// copies values — the hot-path cap/legacy checks only need epochs —
    /// and fails on an iterator error instead of returning a truncated set.
    fn scan_keys_checked(&self, cf_name: &str, prefix: &[u8], limit: usize) -> Result<Vec<Vec<u8>>> {
        let handle = self.cf_handle(cf_name)?;
        let mut iter = self.raw_iterator(&handle);
        iter.seek(prefix);
        let mut out = Vec::new();
        while iter.valid() && out.len() < limit {
            match iter.key() {
                Some(k) if k.starts_with(prefix) => out.push(k.to_vec()),
                _ => break,
            }
            iter.next();
        }
        iter.status().with_context(|| format!("scanning {cf_name} keys"))?;
        Ok(out)
    }

    /// Whether any `CHANNEL_KEYS` row exists at `(scope, epoch)` (keys-only,
    /// bounded by `scan_cap`).
    fn channel_keys_exist_at(&self, scope: &[u8; 32], epoch: u64, scan_cap: usize) -> Result<bool> {
        let keys = self.scan_keys_checked(cf::CHANNEL_KEYS, &scope[..], scan_cap)?;
        Ok(keys.iter().any(|k| epoch_of_key(k) == epoch))
    }

    /// Arbitration state of one channel `(scope, epoch)` for reads. Rows
    /// that predate arbitration (no commit row, but `CHANNEL_KEYS` rows at
    /// the epoch) and epochs below the eviction horizon report `legacy`.
    pub fn key_commit_view(&self, scope: &[u8; 32], epoch: u64) -> Result<KeyCommitView> {
        if let Some(rec) = self.get_key_commit(scope, epoch)? {
            let state = if rec.winner().is_some() { STATE_ARBITRATED } else { STATE_LEGACY };
            return Ok(KeyCommitView { state, record: Some(rec) });
        }
        let evicted = epoch < self.key_commit_scope_meta(scope)?.evicted_below;
        if evicted || self.channel_keys_exist_at(scope, epoch, 8192)? {
            return Ok(KeyCommitView { state: STATE_LEGACY, record: None });
        }
        Ok(KeyCommitView { state: STATE_NONE, record: None })
    }

    /// Highest `CHANNEL_KEY_COMMITS` epoch of a scope (one reverse seek).
    /// Keys only, and an iterator error FAILS CLOSED (round-3 audit N-a):
    /// silently reading 0 would turn every epoch into "new" for the bound.
    fn max_commit_epoch(&self, scope: &[u8; 32]) -> Result<u64> {
        let mut start = scope.to_vec();
        start.extend_from_slice(&u64::MAX.to_be_bytes());
        let handle = self.cf_handle(cf::CHANNEL_KEY_COMMITS)?;
        let mut iter = self.raw_iterator(&handle);
        iter.seek_for_prev(&start);
        // At most two keys: the highest epoch row, or the scope's 32-byte
        // meta row (which sorts before every epoch row of the scope).
        for _ in 0..2 {
            if !iter.valid() {
                break;
            }
            match iter.key() {
                Some(k) if k.starts_with(&scope[..]) => {
                    if k.len() == 40 {
                        return Ok(epoch_of_key(k));
                    }
                }
                _ => break,
            }
            iter.prev();
        }
        iter.status().context("scanning channel_key_commits for the highest epoch")?;
        Ok(0)
    }

    /// Highest epoch known for a scope: max over `CHANNEL_KEYS` rows and
    /// `CHANNEL_KEY_COMMITS` rows (0 if none). Full (bounded) scan — use
    /// [`Self::max_known_key_epoch_fast`] on hot paths.
    pub fn max_known_key_epoch(&self, scope: &[u8; 32]) -> Result<u64> {
        Ok(self.max_channel_key_epoch(scope)?.max(self.max_commit_epoch(scope)?))
    }

    /// [`Self::max_known_key_epoch`] without the `CHANNEL_KEYS` scan once the
    /// migration's Phase A has run: from then on every channel `(scope,
    /// epoch)` that has `CHANNEL_KEYS` rows also has a commit row (Phase A
    /// wrote one for each pre-existing epoch, and every later write comes
    /// with one), so the highest commit row IS the highest epoch.
    pub fn max_known_key_epoch_fast(&self, scope: &[u8; 32]) -> Result<u64> {
        if self.key_commit_legacy_rows_done() {
            self.max_commit_epoch(scope)
        } else {
            self.max_known_key_epoch(scope)
        }
    }

    /// Every `CHANNEL_KEYS` row of a scope (≤ `limit`) WITH values — only the
    /// rare supersede needs values. Fails on an iterator error instead of
    /// silently returning a truncated set (a short scan would under-delete
    /// loser wraps).
    fn scan_scope_rows_checked(&self, scope: &[u8; 32], limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf_keys = self.cf_handle(cf::CHANNEL_KEYS)?;
        let mut iter = self.raw_iterator(&cf_keys);
        iter.seek(&scope[..]);
        let mut out = Vec::new();
        while iter.valid() && out.len() < limit {
            match (iter.key(), iter.value()) {
                (Some(k), Some(v)) if k.starts_with(&scope[..]) => out.push((k.to_vec(), v.to_vec())),
                _ => break,
            }
            iter.next();
        }
        iter.status().context("scanning channel_keys scope")?;
        Ok(out)
    }

    /// Step 7h (l2-node 0.143.0): arbitrate one channel-scope
    /// `ChannelKeyEnvelope` and, if accepted, store it — commit row,
    /// supersede/eviction deletions, `CHANNEL_KEYS` put, `MESSAGES` put and
    /// the `TOTAL_MESSAGES` merge in ONE `WriteBatch` under
    /// `channel_key_envelope_lock`. See the module docs for the rules.
    /// `Conflict`/`Rejected` write nothing.
    pub fn arbitrate_and_store_channel_key(
        &self,
        input: &ChannelKeyArbInput<'_>,
    ) -> Result<ChannelKeyArbOutcome> {
        self.with_channel_key_envelope_lock(|| self.arbitrate_locked(input))
    }

    fn arbitrate_locked(&self, inp: &ChannelKeyArbInput<'_>) -> Result<ChannelKeyArbOutcome> {
        use ChannelKeyArbOutcome as O;
        let scope = &inp.key_scope;
        let epoch = inp.epoch;
        let now = inp.now_ms;

        // ---- Cheap point reads and content checks first: everything below
        // up to the slot handling holds the node-wide key lock without any
        // scan (round-2 audit W-D). ----

        // Private channel floor: keys below it belong to an era that included
        // a since-removed member (P2d). Read under the key lock.
        let floor = self.private_key_epoch_floor(inp.channel_id)?;
        if epoch < floor {
            return Ok(O::Rejected(KeyArbRejection::EpochBelowFloor { floor }));
        }
        let mut scope_meta = self.key_commit_scope_meta(scope)?;
        if epoch < scope_meta.evicted_below {
            return Ok(O::Rejected(KeyArbRejection::EpochEvicted {
                below: scope_meta.evicted_below,
            }));
        }

        let state = match self.get_key_commit(scope, epoch)? {
            Some(rec) => match rec.winner() {
                Some((c, ts)) => EpochState::Arbitrated(rec, c, ts),
                None if rec.state == STATE_LEGACY => EpochState::Legacy(false),
                None => anyhow::bail!("malformed arbitrated channel_key_commits row"),
            },
            // After Phase A every epoch with CHANNEL_KEYS rows has a commit
            // row, so a missing one means "none" without any scan. Before it
            // ran (or if it failed), CHANNEL_KEYS rows at an epoch WITHOUT a
            // commit row predate arbitration: detect them lazily (keys only)
            // so an unfinished migration can never turn a legacy epoch into
            // a fresh arbitration over existing keys.
            None if self.key_commit_legacy_rows_done() => EpochState::None,
            None => {
                if self.channel_keys_exist_at(scope, epoch, inp.scope_cap + 1)? {
                    EpochState::Legacy(true)
                } else {
                    EpochState::None
                }
            }
        };

        let pair = match (inp.key_commitment, inp.key_ts) {
            (Some(c), Some(t)) => Some((t, c)),
            _ => None,
        };
        let is_winner =
            matches!((&state, pair), (EpochState::Arbitrated(_, wc, wts), Some((t, c))) if *wc == c && *wts == t);
        let is_legacy = matches!(state, EpochState::Legacy(_));

        // Sync / backfill ingestion skips the drift check and rate limits,
        // so a peer could replay a back-dated pair through it onto every node
        // it syncs with (round-2 audit W-C). On those paths ONLY wraps of the
        // already recorded winner are accepted. (Defence in depth: no current
        // sync protocol hands a key envelope to the router at all — reconcile
        // refuses them, the other syncs allow-list their own types. A round-5
        // "sync may supersede" rule was therefore unreachable, and would
        // have allowed unbounded supersedes if ever wired; it was removed.)
        if inp.sync && !is_winner {
            return Ok(O::Rejected(KeyArbRejection::SyncNotWinner));
        }
        let Some((kts, c)) = pair.or(if is_legacy { Some((0, [0u8; 32])) } else { None }) else {
            return Ok(O::Rejected(KeyArbRejection::CommitmentRequired));
        };
        // Uniform, content-only freshness rule (create AND supersede): a
        // stale pair may only add wraps of the CURRENT winner. Legacy epochs
        // stay plain first-write-wins.
        if !is_legacy && !is_winner && inp.envelope_ts.saturating_sub(kts) > KEY_TS_MAX_AGE_MS {
            return Ok(O::Rejected(KeyArbRejection::KeyTsStale));
        }
        // Wide sanity bound on NEW epochs (no near-u64::MAX epochs); see
        // `CHANNEL_KEY_EPOCH_MAX_AHEAD` for why it is not tight.
        if matches!(state, EpochState::None) {
            let base = self.max_known_key_epoch_fast(scope)?.max(floor);
            let bound = base.saturating_add(CHANNEL_KEY_EPOCH_MAX_AHEAD);
            if epoch > bound {
                return Ok(O::Rejected(KeyArbRejection::EpochTooFarAhead { bound }));
            }
        }

        let msg_id_hex = hex::encode(inp.msg_id);
        let mut new_commit: Option<KeyCommitRecord> = None;
        let mut is_new_commit_row = false;
        let mut deletions: Vec<Vec<u8>> = Vec::new();

        match state {
            EpochState::Legacy(write_row) => {
                if write_row {
                    new_commit = Some(KeyCommitRecord::legacy(now));
                    is_new_commit_row = true;
                }
            }
            EpochState::None => {
                new_commit = Some(KeyCommitRecord {
                    c: Some(hex::encode(c)),
                    key_ts: Some(kts),
                    author: Some(inp.author.to_string()),
                    msg_id: Some(msg_id_hex.clone()),
                    recorded_at: now,
                    state: STATE_ARBITRATED.to_string(),
                    superseded: Vec::new(),
                });
                is_new_commit_row = true;
            }
            EpochState::Arbitrated(rec, wc, wts) => {
                if !is_winner {
                    // The winner moves ONLY to a strictly better PAIR rank
                    // (a same-C-different-key_ts pair is just another rank).
                    // Nothing else may influence the outcome: e.g. refusing a
                    // commitment that was superseded before made the winner
                    // depend on which envelopes a node happened to see
                    // (round-2 audit W-A) — `superseded` is forensics only.
                    let better = (kts, c) < (wts, wc);
                    let within = !rec.is_final(now);
                    if !(better && within) {
                        return Ok(O::Conflict(KeyCommitWinner {
                            key_commitment: wc,
                            key_ts: wts,
                            author: rec.author.clone(),
                            msg_id: rec.msg_id.as_deref().and_then(decode32),
                            is_final: !within,
                        }));
                    }
                    // SUPERSEDE: drop every wrap at this epoch whose PAIR is
                    // not the new winner's. The only path that copies values.
                    let new_hex = hex::encode(c);
                    let rows = self.scan_scope_rows_checked(scope, inp.scope_cap + 1)?;
                    // Fail closed (round-2 audit N2): more rows than the cap
                    // means the scan cannot be known to be complete, and an
                    // incomplete scan would leave loser wraps behind.
                    if rows.len() > inp.scope_cap {
                        anyhow::bail!("channel_keys scope exceeds its cap; refusing an incomplete supersede");
                    }
                    for (k, v) in &rows {
                        if epoch_of_key(k) != epoch {
                            continue;
                        }
                        let j = serde_json::from_slice::<serde_json::Value>(v).ok();
                        let row_c = j.as_ref().and_then(|j| j.get("key_commitment")?.as_str().map(str::to_string));
                        let row_ts = j.as_ref().and_then(|j| j.get("key_ts")?.as_u64());
                        if row_c.as_deref() != Some(new_hex.as_str()) || row_ts != Some(kts) {
                            deletions.push(k.clone());
                        }
                    }
                    let mut updated = rec.clone();
                    updated.superseded.push(SupersededEntry {
                        c: hex::encode(wc),
                        key_ts: Some(wts),
                        author: rec.author.clone(),
                        at: now,
                    });
                    if updated.superseded.len() > MAX_SUPERSEDED_HISTORY {
                        let excess = updated.superseded.len() - MAX_SUPERSEDED_HISTORY;
                        updated.superseded.drain(..excess);
                    }
                    updated.c = Some(new_hex);
                    updated.key_ts = Some(kts);
                    updated.author = Some(inp.author.to_string());
                    updated.msg_id = Some(msg_id_hex.clone());
                    // recorded_at deliberately unchanged: superseding never
                    // extends the finality horizon.
                    new_commit = Some(updated);
                }
            }
        }

        // Per-scope commit-row cap (only when a NEW epoch row is created).
        // Keys only. Plain lowest-epoch eviction; the eviction horizon rises
        // past the evicted epoch so it can never be re-opened as a fresh
        // arbitration. No epoch is protected (rounds 4-5: protecting a
        // "current" epoch cannot tell an honest rotation from a squatter's,
        // and its side paths were worse than the residual it addressed).
        let mut commit_deletion: Option<Vec<u8>> = None;
        let mut meta_changed = false;
        if is_new_commit_row {
            let commit_rows: Vec<Vec<u8>> = self
                .scan_keys_checked(cf::CHANNEL_KEY_COMMITS, &scope[..], MAX_KEY_COMMITS_PER_SCOPE + 2)?
                .into_iter()
                .filter(|k| k.len() == 40)
                .collect();
            if commit_rows.len() >= MAX_KEY_COMMITS_PER_SCOPE {
                // Ascending big-endian epochs: the first row is the lowest.
                let lowest = epoch_of_key(&commit_rows[0]);
                if lowest >= epoch {
                    return Ok(O::Rejected(KeyArbRejection::EpochEvicted { below: lowest }));
                }
                commit_deletion = Some(commit_rows[0].clone());
                scope_meta.evicted_below = scope_meta.evicted_below.max(lowest.saturating_add(1));
                meta_changed = true;
            }
        }

        // First-write-wins slot for this (target, device, epoch).
        let row_key =
            schema::encode_channel_key(scope, inp.target, "", inp.device_id_hex, epoch);
        let deleted: HashSet<&[u8]> = deletions.iter().map(|k| k.as_slice()).collect();
        // Slots are WRITE-ONCE (first write wins), including against a wrap
        // of the winning pair by the winner's own author. A "winner author
        // may replace" rule was tried and reverted: on a lagging node the
        // recorded winner author is whoever first delivered the PUBLIC pair
        // there, so that rule let a copier overwrite honest wraps and lock
        // the real author out. Slot squat under the winning pair is a
        // documented residual: clients verify H(key_ts, K) == C on every
        // adopted wrap, fail safe and rotate.
        let present = !deleted.contains(row_key.as_slice())
            && self.exists_cf(cf::CHANNEL_KEYS, &row_key)?;
        let mut evict: Option<Vec<u8>> = None;
        if !present {
            // Cap check, keys only (round-2 audit W-D).
            let keys = self.scan_keys_checked(cf::CHANNEL_KEYS, &scope[..], inp.scope_cap + 1)?;
            let live: Vec<&Vec<u8>> = keys.iter().filter(|k| !deleted.contains(k.as_slice())).collect();
            if live.len() >= inp.scope_cap {
                // Scope full: evict the lowest-epoch row, but only to admit a
                // strictly newer epoch (rotation must always fit; old history
                // degrades first). Rows below a private channel's floor are
                // always lower than any accepted epoch, so they go first. A
                // "never evict the newest epochs" guard was tried in round 2
                // and removed: junk under the current pair then made every
                // rotation fail with ScopeFull until a kick (round-3 audit).
                let lowest = live
                    .iter()
                    .map(|k| (epoch_of_key(k), *k))
                    .filter(|(e, _)| *e < epoch)
                    .min_by_key(|(e, _)| *e);
                match lowest {
                    Some((_, lk)) => evict = Some(lk.clone()),
                    None => return Ok(O::Rejected(KeyArbRejection::ScopeFull)),
                }
            }
        }

        let keys_cf = self.cf_handle(cf::CHANNEL_KEYS)?;
        let commits_cf = self.cf_handle(cf::CHANNEL_KEY_COMMITS)?;
        let messages_cf = self.cf_handle(cf::MESSAGES)?;
        let state_cf = self.cf_handle(cf::NODE_STATE)?;
        let mut batch = WriteBatch::default();
        if let Some(rec) = &new_commit {
            batch.put_cf(
                &commits_cf,
                schema::encode_key_commit_key(scope, epoch),
                serde_json::to_vec(rec).context("serializing key commit row")?,
            );
        }
        if let Some(k) = &commit_deletion {
            batch.delete_cf(&commits_cf, k);
        }
        if meta_changed {
            batch.put_cf(
                &commits_cf,
                schema::encode_key_commit_scope_meta_key(scope),
                serde_json::to_vec(&scope_meta).context("serializing scope meta")?,
            );
        }
        for k in &deletions {
            batch.delete_cf(&keys_cf, k);
        }
        if let Some(k) = &evict {
            batch.delete_cf(&keys_cf, k);
        }
        if !present {
            batch.put_cf(&keys_cf, &row_key, inp.record);
            // Only a genuinely NEW slot write persists its envelope (round-4
            // audit W1b): a wrap for an already-filled slot changes nothing,
            // so storing it would let replays of such wraps (each a fresh
            // msg_id) grow MESSAGES and the message counter without bound.
            batch.put_cf(&messages_cf, inp.msg_id, inp.raw_envelope);
            batch.merge_cf(&state_cf, state_keys::TOTAL_MESSAGES, 1i64.to_be_bytes());
        }
        if !batch.is_empty() {
            self.write_batch(batch)?;
        }

        if !deletions.is_empty() {
            info!(
                epoch,
                deleted = deletions.len(),
                key_scope = %hex::encode(scope),
                "Channel key epoch superseded by a better-ranked commitment"
            );
        }
        Ok(if present { O::AlreadyPresent } else { O::Stored })
    }

    /// One-time, sentinel-gated key-epoch arbitration migration (l2-node
    /// 0.143.0). Never fatal to boot: callers log an `Err` and continue.
    ///
    /// * Phase A — write a `legacy` `CHANNEL_KEY_COMMITS` row for every
    ///   channel-scope `(scope, epoch)` present in `CHANNEL_KEYS` that has no
    ///   commit row (re-checked under `channel_key_envelope_lock`, so it can
    ///   never overwrite an arbitrated row). Correctness does not depend on
    ///   this phase — Step 7h detects such epochs lazily — it makes the
    ///   GET endpoint and the on-disk state explicit.
    /// * Phase B — stream `MESSAGES` for channel-scope `ChannelKeyEnvelope`s,
    ///   recompute each one's `CHANNEL_KEYS` row key, and attach `msg_id`
    ///   where the row's `eph_pub`/`nonce`/`wrapped` match (so `GET
    ///   /keys/{scope}?proof=1` can serve the signed envelope for old rows).
    ///   At most `max_messages` rows are scanned per call; progress is kept in
    ///   `KEY_COMMITS_MIGRATION_CURSOR`, so a capped or interrupted pass
    ///   resumes on the next boot.
    ///
    /// Returns `Ok(true)` and sets `KEY_COMMITS_MIGRATED_V1` only when both
    /// phases completed.
    pub fn migrate_channel_key_commits(&self, max_messages: usize, now_ms: u64) -> Result<bool> {
        use crate::messages::envelope::Envelope;
        use crate::messages::types::{key_scope_kind, ChannelKeyEnvelopePayload, MessageType};

        // ---- Phase A ----
        let mut legacy_written = 0u64;
        let mut pending: Vec<([u8; 32], u64)> = Vec::new();
        let mut seen: HashSet<([u8; 32], u64)> = HashSet::new();
        {
            let cf_keys = self.cf_handle(cf::CHANNEL_KEYS)?;
            let mut iter = self.raw_iterator(&cf_keys);
            iter.seek_to_first();
            while iter.valid() {
                if let (Some(k), Some(v)) = (iter.key(), iter.value()) {
                    if k.len() >= 40 {
                        let is_channel = serde_json::from_slice::<serde_json::Value>(v)
                            .ok()
                            .and_then(|j| j.get("scope_kind")?.as_u64())
                            == Some(key_scope_kind::CHANNEL as u64);
                        if is_channel {
                            let mut scope = [0u8; 32];
                            scope.copy_from_slice(&k[..32]);
                            let ep = epoch_of_key(k);
                            if seen.insert((scope, ep)) {
                                pending.push((scope, ep));
                            }
                        }
                    }
                }
                iter.next();
            }
            iter.status().context("iterating channel_keys")?;
        }
        for chunk in pending.chunks(1000) {
            legacy_written += self.with_channel_key_envelope_lock(|| -> Result<u64> {
                let commits_cf = self.cf_handle(cf::CHANNEL_KEY_COMMITS)?;
                let mut batch = WriteBatch::default();
                let mut n = 0u64;
                for (scope, ep) in chunk {
                    // Never re-create a row for an epoch the per-scope cap
                    // evicted: it would count against the cap again (and
                    // could evict a live epoch) — the eviction horizon
                    // already refuses that epoch.
                    if *ep < self.key_commit_scope_meta(scope)?.evicted_below {
                        continue;
                    }
                    let key = schema::encode_key_commit_key(scope, *ep);
                    if !self.exists_cf(cf::CHANNEL_KEY_COMMITS, &key)? {
                        batch.put_cf(&commits_cf, key, serde_json::to_vec(&KeyCommitRecord::legacy(now_ms))?);
                        n += 1;
                    }
                }
                self.write_batch(batch)?;
                Ok(n)
            })?;
        }

        // Phase A complete: from now on every channel epoch with CHANNEL_KEYS
        // rows has a commit row, which lets Step 7h and the epoch-ahead
        // bound skip their scans (`key_commit_legacy_rows_done`).
        self.put_cf(cf::NODE_STATE, state_keys::KEY_COMMITS_LEGACY_ROWS_V1, &1u64.to_be_bytes())?;
        self.set_key_commit_legacy_rows_done();
        info!(legacy_written, "Key-commit migration Phase A complete (legacy commit rows)");

        // ---- Phase B ----
        // Progress log with ETA (round-2 audit N5): the MESSAGES scan is the
        // only potentially long part of boot; operators should see it move.
        let total_estimate = self.estimate_num_keys(cf::MESSAGES).unwrap_or(0);
        let started = std::time::Instant::now();
        let cursor = self.get_cf(cf::NODE_STATE, state_keys::KEY_COMMITS_MIGRATION_CURSOR)?;
        let mut attached = 0u64;
        let mut scanned = 0usize;
        let mut last_key: Option<Vec<u8>> = None;
        let complete;
        {
            let cf_msgs = self.cf_handle(cf::MESSAGES)?;
            let mut iter = self.raw_iterator(&cf_msgs);
            match &cursor {
                Some(c) => {
                    iter.seek(c);
                    if iter.valid() && iter.key() == Some(c.as_slice()) {
                        iter.next();
                    }
                }
                None => iter.seek_to_first(),
            }
            loop {
                if !iter.valid() {
                    iter.status().context("iterating messages")?;
                    complete = true;
                    break;
                }
                if scanned >= max_messages {
                    complete = false;
                    break;
                }
                scanned += 1;
                if let (Some(k), Some(raw)) = (iter.key(), iter.value()) {
                    last_key = Some(k.to_vec());
                    if let Ok(env) = rmp_serde::from_slice::<Envelope>(raw) {
                        if env.msg_type == MessageType::ChannelKeyEnvelope {
                            if let Ok(p) = rmp_serde::from_slice::<ChannelKeyEnvelopePayload>(&env.payload) {
                                if p.scope_kind == key_scope_kind::CHANNEL
                                    && self.attach_msg_id_to_key_row(&p, &env)?
                                {
                                    attached += 1;
                                }
                            }
                        }
                    }
                }
                if scanned.is_multiple_of(MIGRATION_CURSOR_EVERY) {
                    if let Some(lk) = &last_key {
                        self.put_cf(cf::NODE_STATE, state_keys::KEY_COMMITS_MIGRATION_CURSOR, lk)?;
                    }
                    if scanned.is_multiple_of(MIGRATION_CURSOR_EVERY * 50) {
                        let elapsed = started.elapsed().as_secs_f64();
                        let rate = scanned as f64 / elapsed.max(0.001);
                        let remaining = total_estimate.saturating_sub(scanned as u64) as f64;
                        info!(
                            scanned,
                            total_estimate,
                            attached,
                            eta_secs = (remaining / rate.max(1.0)) as u64,
                            "Key-commit migration Phase B (msg_id back-fill) in progress"
                        );
                    }
                }
                iter.next();
            }
        }

        if !complete {
            if let Some(lk) = &last_key {
                self.put_cf(cf::NODE_STATE, state_keys::KEY_COMMITS_MIGRATION_CURSOR, lk)?;
            }
            info!(legacy_written, attached, scanned, "Key-commit migration paused (budget reached); resumes next start");
            return Ok(false);
        }
        self.put_cf(cf::NODE_STATE, state_keys::KEY_COMMITS_MIGRATED_V1, &1u64.to_be_bytes())?;
        if let Err(e) = self.delete_cf(cf::NODE_STATE, state_keys::KEY_COMMITS_MIGRATION_CURSOR) {
            warn!(error = %e, "Key-commit migration: failed to clear resume cursor (harmless)");
        }
        info!(legacy_written, attached, scanned, "Key-commit migration complete");
        Ok(true)
    }

    /// Phase B helper: set `msg_id` on the matching `CHANNEL_KEYS` row when
    /// the row has none and this envelope is provably the one it was built
    /// from: identical wrap (`eph_pub`/`nonce`/`wrapped`) AND identical
    /// `timestamp` AND the envelope's author (device resolved to its wallet
    /// via `DEVICE_WALLET_MAP`) equal to the row's `author`. Without the last
    /// two, anyone could re-sign a copy of a public wrap and get THEIR
    /// envelope served as the row's proof. Field-wise JSON merge under the
    /// key lock. Returns whether a row was updated.
    fn attach_msg_id_to_key_row(
        &self,
        p: &crate::messages::types::ChannelKeyEnvelopePayload,
        env: &crate::messages::envelope::Envelope,
    ) -> Result<bool> {
        let msg_id = &env.msg_id;
        let env_wallet = match self.resolve_wallet(&env.author) {
            Ok(Some(w)) => w,
            _ => env.author.clone(),
        };
        let key = schema::encode_channel_key(&p.key_scope, &p.target, "", &p.device_id, p.epoch);
        self.with_channel_key_envelope_lock(|| -> Result<bool> {
            let Some(bytes) = self.get_cf(cf::CHANNEL_KEYS, &key)? else {
                return Ok(false);
            };
            let Ok(mut rec) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                return Ok(false);
            };
            if rec.get("msg_id").is_some() {
                return Ok(false);
            }
            let same = rec.get("eph_pub").and_then(|v| v.as_str()) == Some(hex::encode(p.eph_pub).as_str())
                && rec.get("nonce").and_then(|v| v.as_str()) == Some(hex::encode(p.nonce).as_str())
                && rec.get("wrapped").and_then(|v| v.as_str()) == Some(hex::encode(&p.wrapped).as_str());
            let same_origin = rec.get("timestamp").and_then(|v| v.as_u64()) == Some(env.timestamp)
                && rec.get("author").and_then(|v| v.as_str()) == Some(env_wallet.as_str());
            if !same || !same_origin {
                return Ok(false);
            }
            let Some(obj) = rec.as_object_mut() else {
                return Ok(false);
            };
            obj.insert("msg_id".into(), serde_json::json!(hex::encode(msg_id)));
            self.put_cf(cf::CHANNEL_KEYS, &key, &serde_json::to_vec(&rec)?)?;
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    //! State-machine, concurrency, persistence and migration tests for the
    //! key-epoch arbitration storage layer (l2-node 0.143.0).
    use super::*;
    use tempfile::TempDir;

    const CID: u64 = 4242;
    const T0: u64 = 1_790_000_000_000;
    const CAP: usize = 4096;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    fn scope() -> [u8; 32] {
        crate::crypto::compute_channel_scope(CID)
    }

    fn private_channel(s: &Storage, floor: u64) {
        let meta = serde_json::json!({ "channel_id": CID, "channel_type": 2u8, "key_epoch_floor": floor });
        s.put_cf(cf::CHANNELS, &CID.to_be_bytes(), meta.to_string().as_bytes()).unwrap();
    }

    fn c(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// One arbitration attempt with the record carrying `key_commitment`.
    #[allow(clippy::too_many_arguments)]
    fn put(
        s: &Storage,
        epoch: u64,
        target: &str,
        commit: Option<([u8; 32], u64)>,
        env_ts: u64,
        now: u64,
        msg: u8,
        scope_cap: usize,
    ) -> ChannelKeyArbOutcome {
        put_as(s, "klv1a", epoch, target, commit, env_ts, now, msg, scope_cap)
    }

    #[allow(clippy::too_many_arguments)]
    fn put_as(
        s: &Storage,
        author: &str,
        epoch: u64,
        target: &str,
        commit: Option<([u8; 32], u64)>,
        env_ts: u64,
        now: u64,
        msg: u8,
        scope_cap: usize,
    ) -> ChannelKeyArbOutcome {
        put_full(s, author, epoch, target, commit, env_ts, now, msg, scope_cap, false)
    }

    #[allow(clippy::too_many_arguments)]
    fn put_full(
        s: &Storage,
        author: &str,
        epoch: u64,
        target: &str,
        commit: Option<([u8; 32], u64)>,
        env_ts: u64,
        now: u64,
        msg: u8,
        scope_cap: usize,
        sync: bool,
    ) -> ChannelKeyArbOutcome {
        let mut rec = serde_json::json!({ "epoch": epoch, "scope_kind": 1, "author": author, "msg_id": hex::encode([msg; 32]) });
        if let Some((cc, kts)) = commit {
            rec["key_commitment"] = serde_json::json!(hex::encode(cc));
            rec["key_ts"] = serde_json::json!(kts);
        }
        let record = serde_json::to_vec(&rec).unwrap();
        let dev = "ab".repeat(32);
        s.arbitrate_and_store_channel_key(&ChannelKeyArbInput {
            key_scope: scope(),
            channel_id: CID,
            epoch,
            target,
            device_id_hex: &dev,
            author,
            key_commitment: commit.map(|x| x.0),
            key_ts: commit.map(|x| x.1),
            envelope_ts: env_ts,
            msg_id: [msg; 32],
            record: &record,
            raw_envelope: b"raw",
            now_ms: now,
            scope_cap,
            sync,
        })
        .unwrap()
    }

    fn row_commitments_at(s: &Storage, epoch: u64) -> Vec<Option<String>> {
        s.prefix_iter_cf(cf::CHANNEL_KEYS, &scope()[..], 10_000)
            .unwrap()
            .into_iter()
            .filter(|(k, _)| epoch_of_key(k) == epoch)
            .map(|(_, v)| {
                serde_json::from_slice::<serde_json::Value>(&v)
                    .unwrap()
                    .get("key_commitment")
                    .and_then(|x| x.as_str())
                    .map(str::to_string)
            })
            .collect()
    }

    #[test]
    fn none_to_arbitrated_then_same_c_and_already_present() {
        let (s, _d) = db();
        assert_eq!(put(&s, 1, "klv1t1", Some((c(5), T0)), T0, T0, 1, CAP), ChannelKeyArbOutcome::Stored);
        let rec = s.get_key_commit(&scope(), 1).unwrap().unwrap();
        assert_eq!(rec.state, STATE_ARBITRATED);
        assert_eq!(rec.c.as_deref(), Some(hex::encode(c(5)).as_str()));
        assert_eq!(rec.recorded_at, T0);
        assert_eq!(rec.msg_id.as_deref(), Some(hex::encode([1u8; 32]).as_str()));
        // Same C → another target stored; same slot → already present.
        assert_eq!(put(&s, 1, "klv1t2", Some((c(5), T0)), T0, T0 + 1, 2, CAP), ChannelKeyArbOutcome::Stored);
        assert_eq!(put(&s, 1, "klv1t2", Some((c(5), T0)), T0, T0 + 2, 3, CAP), ChannelKeyArbOutcome::AlreadyPresent);
        // An AlreadyPresent wrap changes nothing and is NOT persisted
        // (round-4 audit W1b: replays must not grow MESSAGES).
        assert!(!s.message_exists(&[3u8; 32]).unwrap());
        // Same C with a LATER key_ts is a different, worse pair → 409.
        assert!(matches!(
            put(&s, 1, "klv1t3", Some((c(5), T0 + 1)), T0 + 1, T0 + 3, 4, CAP),
            ChannelKeyArbOutcome::Conflict(_)
        ));
        assert!(!s.message_exists(&[4u8; 32]).unwrap(), "a conflict writes nothing");
        assert_eq!(s.get_stat(state_keys::TOTAL_MESSAGES).unwrap(), 2);
        // Same C with an EARLIER key_ts is a better pair → supersede; the
        // deletion predicate compares the PAIR, so the (C, T0) rows go.
        assert_eq!(put(&s, 1, "klv1t3", Some((c(5), T0 - 1)), T0, T0 + 4, 5, CAP), ChannelKeyArbOutcome::Stored);
        assert_eq!(row_commitments_at(&s, 1), vec![Some(hex::encode(c(5)))]);
        let rec = s.get_key_commit(&scope(), 1).unwrap().unwrap();
        assert_eq!(rec.key_ts, Some(T0 - 1));
        assert_eq!(rec.superseded[0].key_ts, Some(T0));
        // A strictly better pair always wins inside the horizon — even with
        // a commitment that was superseded before (`superseded` is
        // forensics only; refusing it made the outcome order-dependent).
        assert_eq!(put(&s, 1, "klv1t4", Some((c(5), T0 - 2)), T0, T0 + 5, 6, CAP), ChannelKeyArbOutcome::Stored);
        assert_eq!(s.get_key_commit(&scope(), 1).unwrap().unwrap().key_ts, Some(T0 - 2));
    }

    /// Round-2 audit W-A: for one set of competing envelopes (all fresh,
    /// all inside the finality horizon), EVERY arrival order must end with
    /// the same winner and the same surviving rows — otherwise two nodes
    /// that saw the same envelopes in different orders fork. Exhaustive
    /// over all 5! = 120 orders, including same-C/different-key_ts pairs
    /// (the B2 shape) and a commitment that is superseded and later
    /// re-appears with a better key_ts.
    #[test]
    fn winner_is_independent_of_arrival_order() {
        let cands: [(u8, u64, &str); 5] = [
            (5, T0 + 10, "klv1a"),
            (5, T0 + 3, "klv1b"),
            (9, T0 + 3, "klv1c"),
            (2, T0 + 7, "klv1d"),
            (9, T0 + 1, "klv1e"),
        ];
        let expected = cands.iter().map(|(cc, kts, _)| (*kts, c(*cc))).min().unwrap();
        let mut idx = [0usize, 1, 2, 3, 4];
        let mut perms = Vec::new();
        permute(&mut idx, 0, &mut perms);
        assert_eq!(perms.len(), 120);
        for perm in perms {
            let (s, _d) = db();
            for (n, i) in perm.iter().enumerate() {
                let (cc, kts, target) = cands[*i];
                let _ = put(&s, 1, target, Some((c(cc), kts)), T0 + 20, T0 + 20 + n as u64, n as u8 + 1, CAP);
            }
            let rec = s.get_key_commit(&scope(), 1).unwrap().unwrap();
            assert_eq!(
                (rec.key_ts, rec.c.clone()),
                (Some(expected.0), Some(hex::encode(expected.1))),
                "order {perm:?}"
            );
            // Exactly the winner's rows survive.
            let rows = row_commitments_at(&s, 1);
            assert_eq!(rows, vec![Some(hex::encode(expected.1))], "order {perm:?}");
        }
    }

    fn permute(a: &mut [usize; 5], k: usize, out: &mut Vec<[usize; 5]>) {
        if k == a.len() {
            out.push(*a);
            return;
        }
        for i in k..a.len() {
            a.swap(k, i);
            permute(a, k + 1, out);
            a.swap(k, i);
        }
    }

    /// Round-2 audit W-B (pinned, documented regression vs 0.142): a node
    /// that never saw an epoch (state `none`) refuses a late cover whose
    /// `key_ts` is more than 15 min old, even though it is the network's
    /// winner — key envelopes are not backfilled, and accepting stale pairs
    /// at `none` would let back-dated keys open epochs. Recovery is
    /// client-side (rotate when the home node reports none / no wrap).
    #[test]
    fn late_cover_at_none_is_stale() {
        let (s, _d) = db();
        let late = T0 + KEY_TS_MAX_AGE_MS + 1;
        assert_eq!(
            put(&s, 1, "klv1late", Some((c(5), T0)), late, late, 1, CAP),
            ChannelKeyArbOutcome::Rejected(KeyArbRejection::KeyTsStale)
        );
        assert!(s.get_key_commit(&scope(), 1).unwrap().is_none(), "nothing recorded");
    }

    /// Sync/backfill (round-2 W-C; round-6: winner wraps ONLY): sync may add
    /// wraps of the recorded winner, never establish an epoch, supersede,
    /// touch legacy epochs or bring in any other pair.
    #[test]
    fn sync_path_accepts_only_recorded_winner_wraps() {
        let (s, _d) = db();
        let sync = |epoch, target: &str, commit, env_ts, now, msg| {
            put_full(&s, "klv1a", epoch, target, commit, env_ts, now, msg, CAP, true)
        };
        // Cannot establish.
        assert_eq!(sync(1, "klv1t", Some((c(5), T0 + 50)), T0 + 50, T0 + 50, 1), ChannelKeyArbOutcome::Rejected(KeyArbRejection::SyncNotWinner));
        put(&s, 1, "klv1t", Some((c(5), T0 + 50)), T0 + 50, T0 + 50, 2, CAP);
        // Winner cover.
        assert_eq!(sync(1, "klv1u", Some((c(5), T0 + 50)), T0 + 50, T0 + 60, 3), ChannelKeyArbOutcome::Stored);
        // A fresh, BETTER pair inside the horizon still cannot supersede.
        assert_eq!(sync(1, "klv1w", Some((c(1), T0 + 40)), T0 + 45, T0 + 80, 4), ChannelKeyArbOutcome::Rejected(KeyArbRejection::SyncNotWinner));
        assert_eq!(s.get_key_commit(&scope(), 1).unwrap().unwrap().c, Some(hex::encode(c(5))));
        // Worse pair / commitment-less → refused.
        assert_eq!(sync(1, "klv1v", Some((c(9), T0 + 60)), T0 + 60, T0 + 70, 5), ChannelKeyArbOutcome::Rejected(KeyArbRejection::SyncNotWinner));
        assert_eq!(sync(1, "klv1v", None, T0, T0 + 70, 6), ChannelKeyArbOutcome::Rejected(KeyArbRejection::SyncNotWinner));
        // Legacy epochs are live-only.
        let dev = "ab".repeat(32);
        s.put_cf(cf::CHANNEL_KEYS, &schema::encode_channel_key(&scope(), "klv1old", "", &dev, 3), br#"{"scope_kind":1}"#).unwrap();
        assert_eq!(sync(3, "klv1n", Some((c(5), T0 + 50)), T0 + 50, T0 + 90, 7), ChannelKeyArbOutcome::Rejected(KeyArbRejection::SyncNotWinner));
    }

    /// Round-3 audit B2: the new-epoch bound is the WIDE sanity bound
    /// (+256 over max(highest known, floor)). A fresh / lagging node — keys
    /// are never backfilled — must still accept honest rotations (the
    /// auditor's X1/X2 reproductions); only absurd jumps are refused.
    #[test]
    fn new_epoch_bound_is_wide_and_never_wedges_lagging_nodes() {
        // X1: fresh home node (federated late; one kick replayed → floor 1)
        // receives the mesh's rotations to 6 and 7.
        let (s, _d) = db();
        private_channel(&s, 1);
        assert_eq!(put(&s, 6, "klv1t", Some((c(5), T0)), T0, T0, 1, CAP), ChannelKeyArbOutcome::Stored);
        assert_eq!(put(&s, 7, "klv1t", Some((c(5), T0)), T0, T0, 2, CAP), ChannelKeyArbOutcome::Stored);
        // X2: node at epoch 3 missed 4 and 5.
        let (s, _d) = db();
        for e in 1..=3u64 {
            assert_eq!(put(&s, e, "klv1t", Some((c(5), T0)), T0, T0, e as u8, CAP), ChannelKeyArbOutcome::Stored);
        }
        assert_eq!(put(&s, 6, "klv1t", Some((c(6), T0)), T0, T0, 10, CAP), ChannelKeyArbOutcome::Stored);
        assert_eq!(put(&s, 5, "klv1t", Some((c(6), T0)), T0, T0, 11, CAP), ChannelKeyArbOutcome::Stored);
        // Absurd jumps are still refused (P2d C1: no u64::MAX epochs).
        let top = 6 + CHANNEL_KEY_EPOCH_MAX_AHEAD;
        assert_eq!(put(&s, top, "klv1t", Some((c(6), T0)), T0, T0, 12, CAP), ChannelKeyArbOutcome::Stored);
        assert_eq!(
            put(&s, u64::MAX, "klv1t", Some((c(6), T0)), T0, T0, 13, CAP),
            ChannelKeyArbOutcome::Rejected(KeyArbRejection::EpochTooFarAhead { bound: top + CHANNEL_KEY_EPOCH_MAX_AHEAD })
        );
        // The private floor counts as known: rotation straight to it works.
        let (s, _d) = db();
        private_channel(&s, 400);
        assert_eq!(put(&s, 400, "klv1t", Some((c(5), T0)), T0, T0, 5, CAP), ChannelKeyArbOutcome::Stored);
    }

    #[test]
    fn corrupt_scope_meta_fails_closed() {
        let (s, _d) = db();
        s.put_cf(cf::CHANNEL_KEY_COMMITS, &schema::encode_key_commit_scope_meta_key(&scope()), b"{not json").unwrap();
        let rec = br#"{"key_commitment":"00"}"#;
        let dev = "ab".repeat(32);
        let r = s.arbitrate_and_store_channel_key(&ChannelKeyArbInput {
            key_scope: scope(),
            channel_id: CID,
            epoch: 1,
            target: "klv1t",
            device_id_hex: &dev,
            author: "klv1a",
            key_commitment: Some(c(5)),
            key_ts: Some(T0),
            envelope_ts: T0,
            msg_id: [1; 32],
            record: rec,
            raw_envelope: b"raw",
            now_ms: T0,
            scope_cap: CAP,
            sync: false,
        });
        assert!(r.is_err());
        assert!(!s.message_exists(&[1; 32]).unwrap());
    }

    /// Round-2 audit N2: a supersede whose scan sees more rows than the cap
    /// cannot know it is complete and must fail closed, not under-delete.
    #[test]
    fn supersede_fails_closed_when_scope_exceeds_cap() {
        let (s, _d) = db();
        put(&s, 1, "klv1a", Some((c(5), T0 + 9)), T0 + 9, T0 + 9, 1, 3);
        put(&s, 1, "klv1b", Some((c(5), T0 + 9)), T0 + 9, T0 + 9, 2, 3);
        put(&s, 1, "klv1c", Some((c(5), T0 + 9)), T0 + 9, T0 + 9, 3, 3);
        let mk = |t: &str| {
            let rec = serde_json::to_vec(&serde_json::json!({"key_commitment": hex::encode(c(1)), "key_ts": T0})).unwrap();
            let dev = "ab".repeat(32);
            s.arbitrate_and_store_channel_key(&ChannelKeyArbInput {
                key_scope: scope(),
                channel_id: CID,
                epoch: 1,
                target: t,
                device_id_hex: &dev,
                author: "klv1a",
                key_commitment: Some(c(1)),
                key_ts: Some(T0),
                envelope_ts: T0 + 10,
                msg_id: [9; 32],
                record: &rec,
                raw_envelope: b"raw",
                now_ms: T0 + 10,
                // A cap BELOW the stored row count (e.g. lowered by an
                // operator or rows from an older cap) → scan is "over".
                scope_cap: 2,
                sync: false,
            })
        };
        assert!(mk("klv1d").is_err(), "refuses an incomplete supersede");
        assert_eq!(row_commitments_at(&s, 1).len(), 3, "nothing deleted");
    }

    #[test]
    fn worse_rank_conflicts_and_writes_nothing() {
        let (s, _d) = db();
        put(&s, 1, "klv1t1", Some((c(5), T0)), T0, T0, 1, CAP);
        // Higher key_ts → worse.
        match put(&s, 1, "klv1t2", Some((c(1), T0 + 10)), T0 + 10, T0 + 20, 2, CAP) {
            ChannelKeyArbOutcome::Conflict(w) => {
                assert_eq!(w.key_commitment, c(5));
                assert_eq!(w.key_ts, T0);
                assert_eq!(w.msg_id, Some([1u8; 32]));
                assert!(!w.is_final);
            }
            o => panic!("{o:?}"),
        }
        // Same key_ts, larger commitment bytes → worse.
        assert!(matches!(put(&s, 1, "klv1t2", Some((c(9), T0)), T0, T0 + 20, 3, CAP), ChannelKeyArbOutcome::Conflict(_)));
        assert!(!s.message_exists(&[2u8; 32]).unwrap());
        assert_eq!(row_commitments_at(&s, 1), vec![Some(hex::encode(c(5)))]);
    }

    #[test]
    fn better_rank_within_finality_supersedes_and_deletes_loser_rows() {
        let (s, _d) = db();
        put(&s, 1, "klv1t1", Some((c(5), T0 + 100)), T0 + 100, T0 + 100, 1, CAP);
        put(&s, 1, "klv1t2", Some((c(5), T0 + 100)), T0 + 100, T0 + 101, 2, CAP);
        // A different epoch's rows are never touched.
        put(&s, 2, "klv1t1", Some((c(7), T0)), T0, T0 + 102, 9, CAP);
        // Better (lower key_ts) inside the horizon → supersede.
        assert_eq!(put(&s, 1, "klv1t3", Some((c(8), T0 + 50)), T0 + 60, T0 + 5_000, 3, CAP), ChannelKeyArbOutcome::Stored);
        assert_eq!(row_commitments_at(&s, 1), vec![Some(hex::encode(c(8)))], "loser rows deleted");
        assert_eq!(row_commitments_at(&s, 2).len(), 1);
        let rec = s.get_key_commit(&scope(), 1).unwrap().unwrap();
        assert_eq!(rec.c.as_deref(), Some(hex::encode(c(8)).as_str()));
        assert_eq!(rec.key_ts, Some(T0 + 50));
        assert_eq!(rec.recorded_at, T0 + 100, "superseding never extends the horizon");
        assert_eq!(rec.superseded.len(), 1);
        assert_eq!(rec.superseded[0].c, hex::encode(c(5)));
        // The old winner is now worse → conflict (no oscillation).
        assert!(matches!(put(&s, 1, "klv1t1", Some((c(5), T0 + 100)), T0 + 100, T0 + 6_000, 4, CAP), ChannelKeyArbOutcome::Conflict(_)));
        // Former loser's slot can be filled with the winner.
        assert_eq!(put(&s, 1, "klv1t1", Some((c(8), T0 + 50)), T0 + 60, T0 + 6_000, 5, CAP), ChannelKeyArbOutcome::Stored);
    }

    #[test]
    fn superseded_history_is_capped_newest_kept() {
        let (s, _d) = db();
        put(&s, 1, "klv1t", Some((c(200), T0 + 100)), T0 + 100, T0 + 100, 1, CAP);
        for i in 0..6u8 {
            let o = put(&s, 1, "klv1t", Some((c(100 - i), T0 + 100)), T0 + 100, T0 + 200 + i as u64, 10 + i, CAP);
            assert_eq!(o, ChannelKeyArbOutcome::Stored);
        }
        let rec = s.get_key_commit(&scope(), 1).unwrap().unwrap();
        assert_eq!(rec.superseded.len(), MAX_SUPERSEDED_HISTORY);
        assert_eq!(rec.superseded.last().unwrap().c, hex::encode(c(96)), "newest superseded kept");
        assert_eq!(rec.c.as_deref(), Some(hex::encode(c(95)).as_str()));
    }

    #[test]
    fn better_rank_after_finality_or_stale_key_ts_conflicts() {
        let (s, _d) = db();
        put(&s, 1, "klv1t1", Some((c(5), T0 + 100)), T0 + 100, T0 + 100, 1, CAP);
        // Past the horizon: final winner, 409 with final=true.
        match put(&s, 1, "klv1t2", Some((c(1), T0)), T0, T0 + 100 + KEY_FINALITY_MS, 2, CAP) {
            ChannelKeyArbOutcome::Conflict(w) => assert!(w.is_final),
            o => panic!("{o:?}"),
        }
        // Inside the horizon but key_ts back-dated > 15 min before the
        // envelope → 400 key_ts_stale (content-only rule).
        let env_ts = T0 + KEY_TS_MAX_AGE_MS + 2;
        assert_eq!(
            put(&s, 1, "klv1t2", Some((c(1), T0)), env_ts, T0 + 1_000, 3, CAP),
            ChannelKeyArbOutcome::Rejected(KeyArbRejection::KeyTsStale)
        );
        assert_eq!(row_commitments_at(&s, 1), vec![Some(hex::encode(c(5)))]);
    }

    #[test]
    fn missing_commitment_policy_and_legacy_fww() {
        let (s, _d) = db();
        // none + commitment-less → 400.
        assert_eq!(put(&s, 1, "klv1t", None, T0, T0, 1, CAP), ChannelKeyArbOutcome::Rejected(KeyArbRejection::CommitmentRequired));
        // arbitrated + commitment-less → 400.
        put(&s, 1, "klv1t", Some((c(5), T0)), T0, T0, 2, CAP);
        assert_eq!(put(&s, 1, "klv1u", None, T0, T0, 3, CAP), ChannelKeyArbOutcome::Rejected(KeyArbRejection::CommitmentRequired));
        // Legacy: a CHANNEL_KEYS row at epoch 3 with no commit row (pre-0.143).
        let dev = "ab".repeat(32);
        let k = schema::encode_channel_key(&scope(), "klv1old", "", &dev, 3);
        s.put_cf(cf::CHANNEL_KEYS, &k, br#"{"scope_kind":1}"#).unwrap();
        assert_eq!(s.key_commit_view(&scope(), 3).unwrap().state, STATE_LEGACY);
        assert_eq!(put(&s, 3, "klv1t", None, T0, T0, 4, CAP), ChannelKeyArbOutcome::Stored, "legacy accepts commitment-less");
        assert_eq!(s.get_key_commit(&scope(), 3).unwrap().unwrap().state, STATE_LEGACY, "legacy row written lazily");
        // Legacy stays FWW: different commitments both store, no conflict.
        assert_eq!(put(&s, 3, "klv1x", Some((c(9), T0)), T0, T0, 5, CAP), ChannelKeyArbOutcome::Stored);
        assert_eq!(put(&s, 3, "klv1y", Some((c(1), T0)), T0, T0, 6, CAP), ChannelKeyArbOutcome::Stored);
        assert_eq!(put(&s, 3, "klv1y", Some((c(1), T0)), T0, T0, 7, CAP), ChannelKeyArbOutcome::AlreadyPresent);
    }

    #[test]
    fn private_floor_rejects_older_epochs() {
        let (s, _d) = db();
        private_channel(&s, 3);
        assert_eq!(
            put(&s, 2, "klv1t", Some((c(5), T0)), T0, T0, 1, CAP),
            ChannelKeyArbOutcome::Rejected(KeyArbRejection::EpochBelowFloor { floor: 3 })
        );
        assert_eq!(put(&s, 3, "klv1t", Some((c(5), T0)), T0, T0, 2, CAP), ChannelKeyArbOutcome::Stored);
    }

    #[test]
    fn commit_rows_capped_per_scope_lowest_epoch_evicted() {
        let (s, _d) = db();
        for e in 1..=MAX_KEY_COMMITS_PER_SCOPE as u64 {
            assert_eq!(put(&s, e, "klv1t", Some((c(5), T0)), T0, T0, (e % 250) as u8, CAP), ChannelKeyArbOutcome::Stored);
        }
        let next = MAX_KEY_COMMITS_PER_SCOPE as u64 + 1;
        assert_eq!(put(&s, next, "klv1t", Some((c(5), T0)), T0, T0, 1, CAP), ChannelKeyArbOutcome::Stored);
        assert!(s.get_key_commit(&scope(), 1).unwrap().is_none(), "lowest epoch row evicted");
        // Epoch 1 can never be re-opened as a fresh arbitration.
        assert_eq!(
            put(&s, 1, "klv1z", Some((c(1), T0)), T0, T0, 2, CAP),
            ChannelKeyArbOutcome::Rejected(KeyArbRejection::EpochEvicted { below: 2 })
        );
        assert_eq!(s.key_commit_view(&scope(), 1).unwrap().state, STATE_LEGACY);
        assert_eq!(s.max_known_key_epoch(&scope()).unwrap(), next);
    }

    #[test]
    fn scope_full_rejects_or_evicts_lower_epoch() {
        let (s, _d) = db();
        put(&s, 2, "klv1a", Some((c(5), T0)), T0, T0, 1, 2);
        put(&s, 2, "klv1b", Some((c(5), T0)), T0, T0, 2, 2);
        // Same epoch, full, nothing lower to evict → 400 key_scope_full.
        assert_eq!(put(&s, 2, "klv1c", Some((c(5), T0)), T0, T0, 3, 2), ChannelKeyArbOutcome::Rejected(KeyArbRejection::ScopeFull));
        assert!(!s.message_exists(&[3u8; 32]).unwrap());
        // Newer epoch → evict the lowest-epoch row.
        assert_eq!(put(&s, 3, "klv1c", Some((c(6), T0)), T0, T0, 4, 2), ChannelKeyArbOutcome::Stored);
        assert_eq!(row_commitments_at(&s, 2).len(), 1);
    }

    #[test]
    fn full_scope_evicts_lowest_epoch_first_so_rotation_always_fits() {
        let (s, _d) = db();
        for i in 0..4u8 {
            let t = format!("klv1t{i}");
            let author = if i == 0 { "klv1w" } else { "klv1sq" };
            assert_eq!(put_as(&s, author, 1, &t, Some((c(5), T0)), T0, T0, i + 1, 4), ChannelKeyArbOutcome::Stored);
        }
        for e in 2..=4u64 {
            assert_eq!(
                put_as(&s, "klv1w", e, "klv1t0", Some((c(7), T0 + 1)), T0 + 1, T0 + 1, 20 + e as u8, 4),
                ChannelKeyArbOutcome::Stored,
                "rotation to {e} fits"
            );
        }
        assert_eq!(row_commitments_at(&s, 1).len(), 1, "three lowest (epoch 1) rows evicted");
        // Rows below a private floor go first even when they are not the
        // only candidates.
        let (s, _d) = db();
        put(&s, 1, "klv1a", Some((c(5), T0)), T0, T0, 1, 2);
        put(&s, 2, "klv1a", Some((c(5), T0)), T0, T0, 2, 2);
        private_channel(&s, 2);
        assert_eq!(put(&s, 3, "klv1a", Some((c(5), T0)), T0, T0, 3, 2), ChannelKeyArbOutcome::Stored);
        assert!(row_commitments_at(&s, 1).is_empty());
        assert_eq!(row_commitments_at(&s, 2).len(), 1);
    }

    #[test]
    fn state_survives_reopen() {
        let dir = TempDir::new().unwrap();
        {
            let s = Storage::open(dir.path()).unwrap();
            put(&s, 1, "klv1t", Some((c(5), T0)), T0, T0, 1, CAP);
        }
        let s = Storage::open(dir.path()).unwrap();
        assert_eq!(s.key_commit_view(&scope(), 1).unwrap().state, STATE_ARBITRATED);
        assert!(matches!(put(&s, 1, "klv1u", Some((c(9), T0)), T0, T0 + 1, 2, CAP), ChannelKeyArbOutcome::Conflict(_)));
        assert_eq!(put(&s, 1, "klv1u", Some((c(5), T0)), T0, T0 + 1, 3, CAP), ChannelKeyArbOutcome::Stored);
    }

    /// Many threads race different commitments (each wrapping its own key to
    /// several targets) for ONE epoch. At quiescence exactly one commitment
    /// — the best-ranked one — owns every row, and the commit row agrees.
    #[test]
    fn threaded_hammering_converges_on_one_commitment() {
        let (s, _d) = db();
        let threads = 12u8;
        let targets = 8u8;
        std::thread::scope(|sc| {
            for t in 0..threads {
                let s = &s;
                sc.spawn(move || {
                    for i in 0..targets {
                        // Rank: key_ts varies per thread; ties broken by bytes.
                        let kts = T0 + ((t as u64 * 7) % 5);
                        let target = format!("klv1t{i}");
                        let _ = put(s, 1, &target, Some((c(t + 1), kts)), T0 + 10, T0 + 10, t * 16 + i, CAP);
                    }
                });
            }
        });
        let best = (0..threads)
            .map(|t| (T0 + ((t as u64 * 7) % 5), c(t + 1)))
            .min()
            .unwrap();
        let rec = s.get_key_commit(&scope(), 1).unwrap().unwrap();
        assert_eq!(rec.c.as_deref(), Some(hex::encode(best.1).as_str()));
        let rows = row_commitments_at(&s, 1);
        assert!(!rows.is_empty());
        assert!(rows.iter().all(|r| r.as_deref() == Some(hex::encode(best.1).as_str())), "{rows:?}");
    }

    #[test]
    fn freshness_rule_is_uniform_but_lets_late_winner_wraps_join() {
        let (s, _d) = db();
        let late = T0 + KEY_TS_MAX_AGE_MS + 1;
        // Create: a stale pair can't open an epoch.
        assert_eq!(
            put(&s, 1, "klv1t1", Some((c(5), T0)), late, late, 1, CAP),
            ChannelKeyArbOutcome::Rejected(KeyArbRejection::KeyTsStale)
        );
        // A fresh one does; much later wraps of the SAME pair still join.
        assert_eq!(put(&s, 1, "klv1t1", Some((c(5), T0)), T0 + 10, T0 + 10, 2, CAP), ChannelKeyArbOutcome::Stored);
        assert_eq!(put(&s, 1, "klv1t2", Some((c(5), T0)), late, late + KEY_FINALITY_MS, 3, CAP), ChannelKeyArbOutcome::Stored);
        // Exactly at the bound is still fresh.
        assert_eq!(
            put(&s, 2, "klv1t1", Some((c(6), T0)), T0 + KEY_TS_MAX_AGE_MS, T0, 4, CAP),
            ChannelKeyArbOutcome::Stored
        );
        // Legacy epochs are not subject to it (first-write-wins as before).
        let dev = "ab".repeat(32);
        s.put_cf(cf::CHANNEL_KEYS, &schema::encode_channel_key(&scope(), "klv1old", "", &dev, 3), br#"{"scope_kind":1}"#).unwrap();
        assert_eq!(put(&s, 3, "klv1t1", Some((c(5), T0)), late, late, 5, CAP), ChannelKeyArbOutcome::Stored);
    }

    /// Slots are write-once: a same-pair wrap by a DIFFERENT author (even
    /// the recorded winner's author) never replaces an existing row. The
    /// reverted "winner author replaces" rule let a copier of the public
    /// pair, recorded as winner author on a lagging node, overwrite honest
    /// wraps there (sdk-js simulation, scenario l).
    #[test]
    fn same_pair_wrap_by_another_author_never_replaces_a_slot() {
        let (s, _d) = db();
        assert_eq!(put_as(&s, "klv1w", 1, "klv1t1", Some((c(5), T0)), T0, T0, 1, CAP), ChannelKeyArbOutcome::Stored);
        assert_eq!(put_as(&s, "klv1sq", 1, "klv1t2", Some((c(5), T0)), T0, T0, 2, CAP), ChannelKeyArbOutcome::Stored);
        for (author, msg) in [("klv1w", 3u8), ("klv1x", 4)] {
            assert_eq!(
                put_as(&s, author, 1, "klv1t2", Some((c(5), T0)), T0, T0, msg, CAP),
                ChannelKeyArbOutcome::AlreadyPresent
            );
        }
        let dev = "ab".repeat(32);
        let row = s.get_cf(cf::CHANNEL_KEYS, &schema::encode_channel_key(&scope(), "klv1t2", "", &dev, 1)).unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&row).unwrap();
        assert_eq!(v["author"], "klv1sq", "first write kept");
    }

    #[test]
    fn legacy_view_reports_final_and_evicted_epochs_stay_refused_after_phase_a() {
        let (s, _d) = db();
        for e in 1..=MAX_KEY_COMMITS_PER_SCOPE as u64 + 1 {
            put(&s, e, "klv1t", Some((c(5), T0)), T0, T0, (e % 250) as u8, CAP);
        }
        assert!(s.get_key_commit(&scope(), 1).unwrap().is_none());
        // CHANNEL_KEYS rows at the evicted epoch 1 still exist; Phase A must
        // NOT re-create a commit row for it (it would count against the cap).
        assert!(s.migrate_channel_key_commits(1_000, T0).unwrap());
        assert!(s.get_key_commit(&scope(), 1).unwrap().is_none(), "evicted epoch not re-created");
        assert_eq!(
            put(&s, 1, "klv1z", None, T0, T0, 9, CAP),
            ChannelKeyArbOutcome::Rejected(KeyArbRejection::EpochEvicted { below: 2 })
        );
        // A real legacy epoch in another scope view: final semantics live in
        // the API (legacy → final:true); the view reports `legacy`.
        assert_eq!(s.key_commit_view(&scope(), 1).unwrap().state, STATE_LEGACY);
    }

    /// Rollback runbook (round-2 audit W-F): `ogmara-node db drop-cf`.
    #[test]
    fn offline_drop_cf_is_allowlisted_lock_safe_and_clears_sentinels() {
        let dir = TempDir::new().unwrap();
        {
            let s = Storage::open(dir.path()).unwrap();
            put(&s, 1, "klv1t", Some((c(5), T0)), T0, T0, 1, CAP);
            assert!(s.migrate_channel_key_commits(10, T0).unwrap());
            // Refused while the DB is open (the node holds the lock).
            assert!(Storage::drop_column_family_offline(dir.path(), cf::CHANNEL_KEY_COMMITS).is_err());
        }
        // Anything but the allow-listed derived CF is refused.
        assert!(Storage::drop_column_family_offline(dir.path(), cf::MESSAGES).is_err());
        assert!(Storage::drop_column_family_offline(dir.path(), "users").is_err());
        assert!(Storage::drop_column_family_offline(dir.path(), cf::CHANNEL_KEY_COMMITS).unwrap());
        // Second run: nothing to do.
        assert!(!Storage::drop_column_family_offline(dir.path(), cf::CHANNEL_KEY_COMMITS).unwrap());
        let mut o = rocksdb::Options::default();
        o.create_if_missing(false);
        let cfs = rocksdb::DB::list_cf(&o, dir.path()).unwrap();
        assert!(!cfs.iter().any(|n| n == cf::CHANNEL_KEY_COMMITS));
        // Sentinels cleared → a re-upgrade re-runs the migration, and the
        // hot path falls back to lazy legacy detection until then.
        let s = Storage::open(dir.path()).unwrap();
        assert_eq!(s.get_stat(state_keys::KEY_COMMITS_MIGRATED_V1).unwrap(), 0);
        assert_eq!(s.get_stat(state_keys::KEY_COMMITS_LEGACY_ROWS_V1).unwrap(), 0);
        assert!(!s.key_commit_legacy_rows_done());
        assert_eq!(s.key_commit_view(&scope(), 1).unwrap().state, STATE_LEGACY, "rows written before the drop read as legacy");
    }

    /// Round-3 audit B1 (data loss): `db drop-cf` on a database whose WAL
    /// still holds NODE_STATE merge records (the node never flushed) must
    /// replay EVERYTHING — the original tool opened NODE_STATE without its
    /// merge operator, replay stopped at the first merge record, and every
    /// later write vanished while the tool reported success.
    #[test]
    fn drop_cf_keeps_every_row_with_wal_resident_merges() {
        let dir = TempDir::new().unwrap();
        let n = 50u8;
        let before;
        {
            let s = Storage::open(dir.path()).unwrap();
            for i in 0..n {
                put(&s, 1, &format!("klv1t{i}"), Some((c(5), T0)), T0, T0, i, CAP);
            }
            // Extra WAL-resident merges, interleaved with later plain writes.
            for _ in 0..500 {
                s.increment_stat(state_keys::TOTAL_MESSAGES).unwrap();
            }
            s.put_cf(cf::NODE_STATE, b"x_after_merges", b"1").unwrap();
            assert!(s.migrate_channel_key_commits(100_000, T0).unwrap());
            before = s.get_stat(state_keys::TOTAL_MESSAGES).unwrap();
            assert_eq!(before, n as u64 + 500);
        }
        assert!(Storage::drop_column_family_offline(dir.path(), cf::CHANNEL_KEY_COMMITS).unwrap());
        let s = Storage::open(dir.path()).unwrap();
        assert_eq!(s.get_stat(state_keys::TOTAL_MESSAGES).unwrap(), before, "counter intact");
        assert_eq!(s.get_cf(cf::NODE_STATE, b"x_after_merges").unwrap().as_deref(), Some(&b"1"[..]));
        for i in 0..n {
            assert!(s.message_exists(&[i; 32]).unwrap(), "message {i}");
        }
        let rows = s.prefix_iter_cf(cf::CHANNEL_KEYS, &scope()[..], 10_000).unwrap();
        assert_eq!(rows.len(), n as usize, "every CHANNEL_KEYS row survives");
        // Merges keep working afterwards.
        s.increment_stat(state_keys::TOTAL_MESSAGES).unwrap();
        assert_eq!(s.get_stat(state_keys::TOTAL_MESSAGES).unwrap(), before + 1);
    }

    fn wal_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut v: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "log"))
            .collect();
        v.sort();
        v
    }

    /// Round-4 audit M02: after `db drop-cf` everything is in SST files —
    /// an open with DEFAULT options (no merge operators, the shape of an
    /// older tool) in absolute-consistency WAL mode succeeds.
    #[test]
    fn after_drop_cf_a_default_options_open_succeeds() {
        let dir = TempDir::new().unwrap();
        {
            let s = Storage::open(dir.path()).unwrap();
            put(&s, 1, "klv1t", Some((c(5), T0)), T0, T0, 1, CAP);
            for _ in 0..20 {
                s.increment_stat(state_keys::TOTAL_MESSAGES).unwrap();
            }
        }
        assert!(Storage::drop_column_family_offline(dir.path(), cf::CHANNEL_KEY_COMMITS).unwrap());
        let mut o = rocksdb::Options::default();
        o.set_wal_recovery_mode(rocksdb::DBRecoveryMode::AbsoluteConsistency);
        let names = rocksdb::DB::list_cf(&o, dir.path()).unwrap();
        let d: Vec<_> = names.iter().map(|n| rocksdb::ColumnFamilyDescriptor::new(n.as_str(), rocksdb::Options::default())).collect();
        assert!(rocksdb::DB::open_cf_descriptors(&o, dir.path(), d).is_ok());
    }

    /// Round-4 audit W2: a database that was not shut down cleanly (torn
    /// WAL tail) makes `db drop-cf` refuse with the actionable message —
    /// and change nothing.
    #[test]
    fn drop_cf_on_unclean_db_says_so_and_changes_nothing() {
        let dir = TempDir::new().unwrap();
        {
            let s = Storage::open(dir.path()).unwrap();
            for _ in 0..50 {
                s.increment_stat(state_keys::TOTAL_MESSAGES).unwrap();
            }
            s.put_cf(cf::CHANNEL_KEY_COMMITS, &[7u8; 40], b"{}").unwrap();
            s.put_cf(cf::NODE_STATE, b"last", b"1").unwrap();
        }
        let wals = wal_files(dir.path());
        let last = wals.last().expect("a WAL");
        let len = std::fs::metadata(last).unwrap().len();
        assert!(len > 3, "WAL holds the unflushed writes");
        std::fs::OpenOptions::new().write(true).open(last).unwrap().set_len(len - 3).unwrap();
        let err = Storage::drop_column_family_offline(dir.path(), cf::CHANNEL_KEY_COMMITS).unwrap_err();
        assert!(format!("{err:#}").contains("not shut down cleanly"), "{err:#}");
        let cfs = rocksdb::DB::list_cf(&rocksdb::Options::default(), dir.path()).unwrap();
        assert!(cfs.iter().any(|n| n == cf::CHANNEL_KEY_COMMITS), "nothing dropped");
        // Recovery path from the message: start once (point-in-time
        // recovery), stop gracefully (flush), rerun.
        {
            let s = Storage::open(dir.path()).unwrap();
            s.flush_all().unwrap();
        }
        assert!(Storage::drop_column_family_offline(dir.path(), cf::CHANNEL_KEY_COMMITS).unwrap());
    }

    #[test]
    fn storage_open_tolerates_unknown_column_families() {
        let dir = TempDir::new().unwrap();
        {
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            let db = rocksdb::DB::open_cf(&opts, dir.path(), ["default", "from_a_newer_release"]).unwrap();
            drop(db);
        }
        let s = Storage::open(dir.path()).expect("unknown CF must not stop boot");
        s.put_cf(cf::CHANNEL_KEY_COMMITS, b"k", b"v").unwrap();
    }

    #[test]
    fn migration_never_attaches_a_forged_copy_of_a_wrap() {
        use crate::messages::envelope::{Envelope, PROTOCOL_VERSION};
        use crate::messages::types::{key_scope_kind, ChannelKeyEnvelopePayload, MessageType};
        let (s, _d) = db();
        let dev = "cd".repeat(32);
        let p = ChannelKeyEnvelopePayload {
            key_scope: scope(),
            scope_kind: key_scope_kind::CHANNEL,
            epoch: 1,
            target: "klv1t".into(),
            device_id: dev.clone(),
            peer: None,
            channel_id: Some(CID),
            eph_pub: [1; 32],
            nonce: [2; 24],
            wrapped: vec![3; 48],
            key_commitment: None,
            key_ts: None,
        };
        let rec = serde_json::json!({
            "eph_pub": hex::encode(p.eph_pub), "nonce": hex::encode(p.nonce),
            "wrapped": hex::encode(&p.wrapped), "epoch": 1, "scope_kind": 1,
            "author": "klv1genuine", "timestamp": T0,
        });
        let k = schema::encode_channel_key(&scope(), "klv1t", "", &dev, 1);
        s.put_cf(cf::CHANNEL_KEYS, &k, rec.to_string().as_bytes()).unwrap();
        let env = |id: u8, author: &str, ts: u64| Envelope {
            version: PROTOCOL_VERSION,
            msg_type: MessageType::ChannelKeyEnvelope,
            msg_id: [id; 32],
            author: author.into(),
            timestamp: ts,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&p).unwrap(),
            signature: vec![0; 64],
            relay_path: vec![],
        };
        // Forged copies (same wrap) sort FIRST: other author / other timestamp.
        for e in [env(0x01, "klv1attacker", T0), env(0x02, "klv1genuine", T0 + 1), env(0x09, "klv1genuine", T0)] {
            s.store_message(&e.msg_id, &rmp_serde::to_vec_named(&e).unwrap()).unwrap();
        }
        assert!(s.migrate_channel_key_commits(100, T0).unwrap());
        let v: serde_json::Value = serde_json::from_slice(&s.get_cf(cf::CHANNEL_KEYS, &k).unwrap().unwrap()).unwrap();
        assert_eq!(v["msg_id"], hex::encode([0x09u8; 32]), "only the genuine (author, timestamp) match is attached");
    }

    /// Lock-hold benchmark (W-D): time `arbitrate_and_store_channel_key`
    /// (which runs entirely under `channel_key_envelope_lock`) on a scope
    /// already holding ~4000 rows. Run with
    /// `cargo test lock_hold_bench -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn lock_hold_bench() {
        let (s, _d) = db();
        for i in 0..4000u32 {
            let t = format!("klv1fill{i}");
            put(&s, 1, &t, Some((c(5), T0)), T0, T0, (i % 250) as u8, CAP);
        }
        let n = 300u32;
        let t0 = std::time::Instant::now();
        for i in 0..n {
            let t = format!("klv1new{i}");
            put(&s, 1, &t, Some((c(5), T0)), T0, T0, (i % 250) as u8, CAP);
        }
        let new_slot = t0.elapsed() / n;
        let t0 = std::time::Instant::now();
        for i in 0..n {
            put(&s, 1, "klv1fill7", Some((c(5), T0)), T0, T0, (i % 250) as u8, CAP);
        }
        let present = t0.elapsed() / n;
        let t0 = std::time::Instant::now();
        for i in 0..n {
            put(&s, 1, "klv1x", Some((c(9), T0 + 1)), T0 + 1, T0, (i % 250) as u8, CAP);
        }
        let conflict = t0.elapsed() / n;
        println!("LOCK-HOLD new_slot={new_slot:?} already_present={present:?} conflict={conflict:?}");
    }

    #[test]
    fn migration_writes_legacy_rows_backfills_msg_id_and_resumes() {
        use crate::messages::envelope::{Envelope, PROTOCOL_VERSION};
        use crate::messages::types::{key_scope_kind, ChannelKeyEnvelopePayload, MessageType};
        let (s, _d) = db();
        let dev = "cd".repeat(32);
        let mk = |epoch: u64, target: &str, n: u8| ChannelKeyEnvelopePayload {
            key_scope: scope(),
            scope_kind: key_scope_kind::CHANNEL,
            epoch,
            target: target.to_string(),
            device_id: dev.clone(),
            peer: None,
            channel_id: Some(CID),
            eph_pub: [n; 32],
            nonce: [n; 24],
            wrapped: vec![n; 48],
            key_commitment: None,
            key_ts: None,
        };
        // Two legacy rows (epochs 1, 2) as the pre-0.143 apply arm wrote them,
        // plus their raw envelopes in MESSAGES, plus one unrelated message.
        for (i, (epoch, target)) in [(1u64, "klv1a"), (2u64, "klv1b")].into_iter().enumerate() {
            let p = mk(epoch, target, i as u8 + 1);
            let rec = serde_json::json!({
                "eph_pub": hex::encode(p.eph_pub), "nonce": hex::encode(p.nonce),
                "wrapped": hex::encode(&p.wrapped), "epoch": epoch, "scope_kind": 1,
                "author": "klv1x", "timestamp": T0,
            });
            let k = schema::encode_channel_key(&scope(), target, "", &dev, epoch);
            s.put_cf(cf::CHANNEL_KEYS, &k, rec.to_string().as_bytes()).unwrap();
            let env = Envelope {
                version: PROTOCOL_VERSION,
                msg_type: MessageType::ChannelKeyEnvelope,
                msg_id: [0x10 + i as u8; 32],
                author: "klv1x".into(),
                timestamp: T0,
                lamport_ts: 0,
                payload: rmp_serde::to_vec_named(&p).unwrap(),
                signature: vec![0; 64],
                relay_path: vec![],
            };
            s.store_message(&env.msg_id, &rmp_serde::to_vec_named(&env).unwrap()).unwrap();
        }
        s.store_message(&[0x01; 32], b"not an envelope").unwrap();

        // Budget 1 → partial pass, cursor saved, sentinel NOT set.
        assert!(!s.migrate_channel_key_commits(1, T0).unwrap());
        assert_eq!(s.get_stat(state_keys::KEY_COMMITS_MIGRATED_V1).unwrap(), 0);
        assert!(s.get_cf(cf::NODE_STATE, state_keys::KEY_COMMITS_MIGRATION_CURSOR).unwrap().is_some());
        // Phase A already ran fully.
        assert_eq!(s.get_key_commit(&scope(), 1).unwrap().unwrap().state, STATE_LEGACY);
        assert_eq!(s.get_key_commit(&scope(), 2).unwrap().unwrap().state, STATE_LEGACY);
        // Resume to completion.
        let mut rounds = 0;
        while !s.migrate_channel_key_commits(1, T0).unwrap() {
            rounds += 1;
            assert!(rounds < 10);
        }
        assert_eq!(s.get_stat(state_keys::KEY_COMMITS_MIGRATED_V1).unwrap(), 1);
        assert!(s.get_cf(cf::NODE_STATE, state_keys::KEY_COMMITS_MIGRATION_CURSOR).unwrap().is_none());
        for (i, (epoch, target)) in [(1u64, "klv1a"), (2u64, "klv1b")].into_iter().enumerate() {
            let k = schema::encode_channel_key(&scope(), target, "", &dev, epoch);
            let v: serde_json::Value = serde_json::from_slice(&s.get_cf(cf::CHANNEL_KEYS, &k).unwrap().unwrap()).unwrap();
            assert_eq!(v["msg_id"], hex::encode([0x10 + i as u8; 32]));
        }
        // Idempotent; never overwrites an arbitrated row.
        s.put_cf(
            cf::CHANNEL_KEY_COMMITS,
            &schema::encode_key_commit_key(&scope(), 1),
            &serde_json::to_vec(&KeyCommitRecord {
                c: Some(hex::encode(c(5))),
                key_ts: Some(T0),
                author: None,
                msg_id: None,
                recorded_at: T0,
                state: STATE_ARBITRATED.into(),
                superseded: vec![],
            })
            .unwrap(),
        )
        .unwrap();
        assert!(s.migrate_channel_key_commits(100, T0).unwrap());
        assert_eq!(s.get_key_commit(&scope(), 1).unwrap().unwrap().state, STATE_ARBITRATED);
    }
}
