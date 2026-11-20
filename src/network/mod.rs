//! libp2p network layer — peer discovery, GossipSub, sync protocol.
//!
//! Handles all peer-to-peer communication using libp2p (spec 3.1).
//! Components:
//! - Peer discovery: mDNS (local), Kademlia DHT (global), bootstrap nodes
//! - GossipSub: pub/sub message propagation across topic channels
//! - Request/Response: sync protocol for on-demand content fetching
//! - Identify: peer identification and capability exchange

pub mod behaviour;
pub mod budget;
pub mod dm_sync;
pub mod gossip;
pub mod hot_topics;
pub mod mesh_stats;
pub mod presence;
pub mod identity_sync;
pub mod private_channel_sync;
pub mod news_sync;
pub mod reconcile;
pub mod sc_discovery;
pub mod snapshot;
pub mod snapshot_client;
pub mod sync;
pub mod onion_transport;
pub mod tor;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{kad, Multiaddr, PeerId, Swarm};
use tracing::{debug, error, info, warn};

use crate::api::state::ConnectedPeerInfo;
use crate::config::Config;
use crate::messages::envelope::Envelope;
use crate::messages::router::{MessageRouter, RouteResult};
use crate::metrics::counters::NetworkCounters;
use crate::notifications::engine::NotificationEngine;
use crate::storage::identity::IdentityResolver;
use crate::storage::rocks::Storage;
use crate::storage::schema;

use self::behaviour::{OgmaraBehaviour, OgmaraBehaviourEvent};
use self::gossip::TopicManager;
use self::snapshot::SharedSnapshotCache;

/// Peers queued for reconnection after disconnect, with exponential backoff.
struct ReconnectEntry {
    peer_id: PeerId,
    addr: Multiaddr,
    next_attempt: tokio::time::Instant,
    backoff_secs: u64,
    attempts: u32,
}

/// Maximum reconnection attempts before giving up on a peer.
const MAX_RECONNECT_ATTEMPTS: u32 = 10;
/// Base backoff for reconnection attempts (seconds).
const RECONNECT_BASE_SECS: u64 = 5;
/// Maximum backoff cap (seconds).
const RECONNECT_MAX_SECS: u64 = 300;

/// Requester-side abort threshold (audit final pre-mainnet W9): after this
/// many CONSECUTIVE backfill pages with zero admitted envelopes (whether
/// empty, fully cross-scope-dropped, or fully router-rejected), stop
/// paging that session — the responder is stalling, not making progress.
/// Shared across all four paginated backfill protocols (reconcile,
/// identity-sync, news-sync, dm-sync); a legitimate large channel/wallet/
/// feed keeps `admitted > 0` on nearly every real page, so this has a low
/// false-positive rate against honest peers while stopping a peer that
/// simply claims `has_more: true` forever with garbage.
pub(crate) const MAX_CONSECUTIVE_UNPRODUCTIVE_PAGES: u32 = 5;
/// Requester-side hard backstop on total pages per backfill session,
/// regardless of productivity — bounds worst-case round-trips even
/// against a peer that evades the consecutive-unproductive check above by
/// interleaving one throwaway-valid envelope periodically. Comfortably
/// above any HONEST peer's worst case (reconcile's own
/// `total_envelopes_cap` default of 200k ÷ 1000/page = 200 pages;
/// dm/news/identity-sync's own caps are 4-5k ÷ 200/page ≈ 20-25 pages).
/// This bound on PAGE COUNT is only meaningful because each response
/// handler separately caps PAGE SIZE too (security-audit follow-up): a
/// malicious responder isn't bound by any protocol's own
/// `MAX_ENVELOPES_PER_RESPONSE`, so without that companion check this
/// constant alone wouldn't actually bound total verification work — see
/// each `handle_*_event`'s oversized-page guard, right before its
/// envelope-verification loop.
pub(crate) const MAX_PAGES_PER_SESSION: u32 = 500;

/// Max inbound backfill responses (private-channel sync + public
/// reconcile) being BUILT concurrently on tokio's blocking pool (round 4).
/// The builds were moved off the swarm event loop
/// (`tokio::task::spawn_blocking`); this node-wide bound keeps a crowd of
/// peers from occupying the blocking pool.
///
/// Round-5 C-W1: only a SESSION-STARTING request (no cursor: a first
/// metadata / legacy / reconcile page) that finds every slot busy is
/// answered `server_capped`. A requester treats `server_capped` as the end
/// of its session — there is no in-session retry; the next attempt is a
/// later sweep that starts over from the first page — so refusing a
/// CONTINUATION page (cursor present) threw away the session's progress
/// and, under the 0.137.0 peer comparison, made a busy honest peer look
/// uninformative. A continuation page instead waits up to
/// `CONTINUATION_BUILD_SLOT_WAIT` for a slot (`responder_build_slot`).
const MAX_CONCURRENT_RESPONDER_BUILDS: usize = 8;

/// Max continuation requests waiting node-wide for a responder build slot
/// (round-5 C-W1). Each waiter also holds its per-peer responder slot, so
/// one peer can hold at most its per-peer concurrency of these; past this
/// bound a continuation request is answered `server_capped` like a
/// session-starting one. "Continuation" is the request's own claim (a
/// cursor is not authenticated), so this bound — not the claim — is what
/// limits the waiting.
const MAX_CONTINUATION_BUILD_WAITERS: usize = 16;

/// How long a continuation request waits for a free build slot before it
/// is answered `server_capped` (round-5 C-W1). Far below the protocols'
/// 45 s request timeout.
const CONTINUATION_BUILD_SLOT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Outcome of `NetworkService::responder_build_slot`.
enum BuildSlot {
    /// A build slot is free: build now.
    Now(tokio::sync::OwnedSemaphorePermit),
    /// No build slot, but this continuation request may wait for one; the
    /// permit is its `MAX_CONTINUATION_BUILD_WAITERS` slot.
    Wait(tokio::sync::OwnedSemaphorePermit),
    /// Answer `server_capped` now.
    Refuse,
}

/// The decision behind `NetworkService::responder_build_slot` (pure over
/// the two semaphores, for tests).
fn pick_build_slot(
    build_permits: &Arc<tokio::sync::Semaphore>,
    waiter_permits: &Arc<tokio::sync::Semaphore>,
    continuation: bool,
) -> BuildSlot {
    if let Ok(p) = build_permits.clone().try_acquire_owned() {
        return BuildSlot::Now(p);
    }
    if continuation {
        if let Ok(w) = waiter_permits.clone().try_acquire_owned() {
            return BuildSlot::Wait(w);
        }
    }
    BuildSlot::Refuse
}

/// Wait up to `CONTINUATION_BUILD_SLOT_WAIT` for a build slot. `Ok` = the
/// build slot (the waiter slot is released); `Err` = timed out, returning
/// the waiter slot so it can ride along with the `server_capped` response
/// (keeping `deferred_response_tx`'s in-flight items bounded).
async fn wait_for_build_slot(
    build_permits: Arc<tokio::sync::Semaphore>,
    waiter: tokio::sync::OwnedSemaphorePermit,
) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::OwnedSemaphorePermit> {
    match tokio::time::timeout(CONTINUATION_BUILD_SLOT_WAIT, build_permits.acquire_owned()).await {
        Ok(Ok(permit)) => {
            drop(waiter);
            Ok(permit)
        }
        _ => Err(waiter),
    }
}

/// A backfill response built off the swarm event loop, handed back to the
/// loop (which alone may touch the swarm) to be sent. The responder
/// guard rides along so the per-peer concurrency slot is held until the
/// response has actually been handed to libp2p — the same window as when
/// the build ran inline — and so does the node-wide slot (`_build_permit`:
/// the build slot, or for a continuation request that timed out waiting,
/// its waiter slot), which therefore also bounds how many finished
/// responses can be queued.
enum DeferredResponse {
    PrivateChannelSync {
        peer: PeerId,
        channel: libp2p::request_response::ResponseChannel<private_channel_sync::PrivateChannelSyncResponse>,
        response: private_channel_sync::PrivateChannelSyncResponse,
        _guard: private_channel_sync::PrivateChannelSyncResponderGuard,
        _build_permit: tokio::sync::OwnedSemaphorePermit,
    },
    Reconcile {
        peer: PeerId,
        channel_id: u64,
        channel: libp2p::request_response::ResponseChannel<reconcile::ReconcileResponse>,
        response: reconcile::ReconcileResponse,
        _guard: reconcile::ResponderGuard,
        _build_permit: tokio::sync::OwnedSemaphorePermit,
    },
}

/// How long `finalize_reconcile_comparison` waits for every fanout
/// candidate to answer a fresh trigger's first page before deciding with
/// whoever has answered so far (l2-node 0.137.0). Deliberately well under
/// the protocol's 45s request timeout (`network::behaviour`) — a real
/// peer on a LAN/testnet answers in well under a second; this just bounds
/// how long one slow or dead candidate can hold up the others.
const RECONCILE_COMPARE_WINDOW: std::time::Duration = std::time::Duration::from_secs(3);

/// Soft cap on concurrently-OPEN `pending_reconcile_comparisons` entries
/// (l2-node 0.137.0). Security-audit finding (2026-09-30, round 1): unlike
/// the pre-0.137.0 design (which processed and dropped one response at a
/// time), a comparison window holds every informative candidate's FULL
/// `ReconcileResponse` in memory for up to `RECONCILE_COMPARE_WINDOW` —
/// and node startup (`src/node.rs`) can call `subscribe_channel` for up
/// to 100,000 channels in a tight loop with no throttling between
/// iterations, each opening its own comparison. Without a cap, a node
/// with a large, mostly-incomplete channel set could have thousands of
/// comparisons open at once right after startup (or after this very
/// version upgrade), each buffering up to `fanout` responses sized by
/// the operator's own `max_envelopes_per_response`/`total_envelopes_cap`
/// knobs — unbounded aggregate memory pressure on a hot, automatic path.
/// `maybe_trigger_backfill` refuses to open a new comparison past this
/// cap, releasing `reconcile_triggered` so the periodic retry sweep
/// picks the channel up on a later tick instead — this bounds worst-case
/// concurrent memory to a fixed, computable multiple of the existing
/// per-response caps, independent of total channel count.
///
/// Security-audit finding (2026-09-30, round 2): each buffered
/// `ReconcileResponse` can be as large as the wire cap (~10 MiB CBOR,
/// `config.rs`'s `max_envelopes_per_response` validation), and a
/// comparison holds up to `fanout + 1` (the reprobe extra) of them at
/// once. An earlier value of 64 here bounded worst case to 64 × 4 ×
/// 10 MiB ≈ 2.5 GB at the default `fanout = 3` (≈ 11 GB at the
/// configurable ceiling `fanout = 16`) — finite, but not obviously
/// "small" for the modest VPS-class hardware this project targets.
/// Lowered to keep the default-config worst case in the hundreds-of-MB
/// range instead; `catchup_batch_size`'s own default (25) already means
/// a single periodic-sweep tick naturally exceeds this, so the
/// remainder just waits for the next 30s tick rather than being able to
/// trigger all at once — graceful degradation, not a functional loss.
const MAX_CONCURRENT_RECONCILE_COMPARISONS: usize = 16;

/// Soft cap on distinct PeerIds tracked by `peer_reconcile_health`
/// between prunes (l2-node 0.137.0) — mirrors `GOSSIP_RATE_LIMITER_SOFT_
/// CAP`'s defense against a Sybil flood of unique PeerIds growing the
/// map without bound (a fresh keypair is free to mint). Existing peers
/// keep being tracked even at the cap; only new-peer inserts are
/// refused.
const PEER_RECONCILE_HEALTH_SOFT_CAP: usize = 16_384;

/// How long a `peer_reconcile_health` entry survives with no comparison
/// touching it before the periodic prune (piggybacked on
/// `mesh_stats_interval`, same as `gossip_rate_limiter`/`gossip_app_
/// score`) drops it (l2-node 0.137.0). Generous relative to the default
/// `[backfill] stale_peer_reprobe_hours` (24h) so ordinary reprobe
/// cadence doesn't itself cause churn — see `PeerReconcileHealth`'s doc
/// comment for why losing this bookkeeping early is harmless regardless.
const PEER_RECONCILE_HEALTH_MAX_IDLE: std::time::Duration =
    std::time::Duration::from_secs(7 * 24 * 3600);

/// Per-peer non-presence gossip rate limit (audit final pre-mainnet W10):
/// max messages accepted from a single peer within [`GOSSIP_RATE_WINDOW`]
/// before `handle_swarm_event` starts reporting `Ignore` without running
/// `handle_gossip_message` at all. Generous for legitimate chat/news/
/// control-message traffic relayed across the mesh; far below flood rates
/// (an attacker holding the single-threaded swarm event loop hostage needs
/// to send fast and continuously to matter).
const GOSSIP_RATE_LIMIT_PER_WINDOW: u32 = 50;
/// Window size for [`GOSSIP_RATE_LIMIT_PER_WINDOW`]. Fixed-window (not
/// sliding/token-bucket) — simplest correct implementation for a
/// single-owner, no-lock counter; the boundary-doubling edge case (up to
/// ~2x burst across a window boundary) is an acceptable tradeoff at this
/// generosity of limit.
const GOSSIP_RATE_WINDOW: Duration = Duration::from_secs(1);
/// Soft cap on distinct PeerIds tracked by `gossip_rate_limiter` /
/// `gossip_app_score` between prunes — mirrors `PresenceRateLimiter`'s
/// `PRESENCE_RATE_LIMITER_SOFT_CAP` defense against a Sybil flood of
/// unique PeerIds growing either map without bound. Existing peers keep
/// being tracked even at the cap; only new-peer inserts are refused.
const GOSSIP_RATE_LIMITER_SOFT_CAP: usize = 16_384;
/// Penalty applied to a peer's tracked P5 app-score on each
/// `RouteResult::Invalid` verdict (genuine crypto/structural invalidity —
/// the only classification in `handle_gossip_message` that represents
/// attacker-grade badness; `Rejected`/`PowRequired`/`Duplicate` cover
/// honest peers and are left untouched). With gossipsub's default
/// `app_specific_weight` (10.0), reaching `graylist_threshold` (-80) from
/// the P5 contribution alone needs a tracked score of -8 — i.e. a burst
/// of `INVALID_MESSAGE_SCORE_PENALTY.abs()`-scaled invalid messages
/// crosses it in a handful of messages, not one.
const INVALID_MESSAGE_SCORE_PENALTY: i64 = 2;
/// Recovery nudge applied on each `RouteResult::Accepted` verdict.
/// Deliberately smaller than [`INVALID_MESSAGE_SCORE_PENALTY`] (fast
/// penalty, slow recovery) so a peer can't stay just under threshold by
/// interleaving one good message per bad one.
const VALID_MESSAGE_SCORE_RECOVERY: i64 = 1;
/// Floor on the tracked P5 app-score — bounds how negative a single
/// peer's score can go so a long-sustained flood doesn't grow the
/// pushed value without bound (gossipsub's own thresholds already stop
/// mattering well above this floor; it's a sanity bound, not a tuning
/// knob).
const GOSSIP_APP_SCORE_FLOOR: i64 = -100;
/// Staleness threshold for pruning `gossip_app_score` entries (Security
/// Audit, W10 follow-up — see the field doc on
/// `NetworkService::gossip_app_score`). Matches gossipsub's own default
/// `PeerScoreParams::retain_score` (1 hour): a disconnected peer's
/// NATIVE gossipsub score state survives that long before gossipsub
/// itself forgets it, so this node's own tracked P5 contribution
/// shouldn't be forgotten any sooner — pruning at the same cadence
/// keeps a reconnecting peer's app-score picking back up consistently
/// with its native score, rather than getting a clean slate early.
const GOSSIP_APP_SCORE_MAX_IDLE: Duration = Duration::from_secs(3600);

/// DM retention reaper (audit final pre-mainnet W11, l2-node 0.101.0+):
/// max rows actually DELETED per sweep, per pass. Bounds the write cost of
/// one `dm_reap_interval` tick.
const DM_REAP_BATCH_LIMIT: usize = 2_000;
/// DM retention reaper: max rows FETCHED/examined per sweep, per pass —
/// bounds wall-clock/read cost even when a sweep's batch is dominated by
/// rows that turn out not to be expired yet (e.g. one very active
/// conversation/wallet). Each pass uses a simple linear scan over this
/// batch (no seek-ahead-past-a-whole-group optimization): every row's
/// timestamp is checked individually, and non-expired rows are simply
/// skipped rather than jumping the RocksDB seek position. This trades a
/// small amount of steady-state efficiency for a large conversation/wallet
/// (its still-fresh rows get re-examined, not re-deleted, on repeated
/// ticks until they age out) for much simpler, easier-to-verify logic — no
/// manual 256-bit big-endian increment/overflow handling. Correctness is
/// unaffected either way: the persisted cursor always advances past the
/// examined batch, so every sweep makes forward progress and nothing is
/// ever missed or double-processed.
const DM_REAP_MAX_ROWS_EXAMINED: usize = 20_000;

/// Per-peer state for the non-presence gossip rate limiter
/// (`NetworkService::gossip_rate_limiter`).
struct GossipRateWindow {
    /// Start of the current fixed window.
    window_start: Instant,
    /// Messages counted in the current window.
    count: u32,
}

/// Per-peer state for `NetworkService::gossip_app_score`.
struct GossipAppScoreEntry {
    /// Tracked raw P5 score, clamped to [`GOSSIP_APP_SCORE_FLOOR`], `0`.
    score: i64,
    /// Last time this entry was touched by `adjust_gossip_app_score`.
    /// Drives staleness-based pruning — see [`GOSSIP_APP_SCORE_MAX_IDLE`].
    last_touched: Instant,
}

impl GossipRateWindow {
    /// Pure fixed-window policy, factored out of
    /// `NetworkService::check_gossip_rate_limit` so it's unit-testable
    /// without a live `Instant` clock or a constructed swarm (audit final
    /// pre-mainnet W10 — mirrors W9's note that this file has no
    /// precedent for testing swarm-event-handler bodies directly; this
    /// factoring keeps the actual policy logic covered anyway). Mutates
    /// `self` in place and returns whether the message may proceed.
    fn check_and_record(&mut self, now: Instant, limit: u32, window: Duration) -> bool {
        if now.duration_since(self.window_start) >= window {
            self.window_start = now;
            self.count = 1;
            true
        } else if self.count < limit {
            self.count += 1;
            true
        } else {
            false
        }
    }
}

/// Pure clamp-and-combine for the P5 app-score adjustment, factored out
/// of `NetworkService::adjust_gossip_app_score` for unit testing (audit
/// final pre-mainnet W10).
fn clamp_gossip_app_score(current: i64, delta: i64, floor: i64) -> i64 {
    (current + delta).clamp(floor, 0)
}

/// Pure planning step for the DM retention reaper's Pass A/Pass C (audit
/// final pre-mainnet W11): given a batch of `DM_MESSAGES`- or
/// `DM_EDIT_DELETE_MSGS`-shaped rows (keyed
/// `conversation_id(32)++timestamp_be(8)++msg_id(32)`) and a cutoff,
/// returns the keys to delete (capped at `batch_limit`) and the next cursor
/// to resume from (`None` means the batch was empty — wrap to the start of
/// the CF). No I/O — factored out purely so the cutoff/key-parsing logic is
/// unit-testable without a live `Storage`/swarm (this campaign's established
/// workaround, see W10's `GossipRateWindow::check_and_record`).
fn plan_dm_msg_shaped_reap(
    rows: &[(Vec<u8>, Vec<u8>)],
    cutoff_ms: u64,
    batch_limit: usize,
) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
    if rows.is_empty() {
        return (Vec::new(), None);
    }
    let mut to_delete = Vec::new();
    let mut last_key: &[u8] = &rows[0].0;
    for (key, _) in rows {
        // Code Audit follow-up (W11): `last_key` must only advance to a row
        // this iteration actually EXAMINES. Setting it before the
        // batch-limit check meant the cursor could skip past a row whose
        // expiry was never evaluated — that row would then never be
        // reconsidered by any future sweep (its key sorts before the
        // persisted cursor forever), permanently orphaning it from the
        // reaper regardless of how expired it later becomes.
        if to_delete.len() >= batch_limit {
            break;
        }
        last_key = key;
        if key.len() != 72 {
            continue; // defensive — malformed key, not this reaper's job to fix
        }
        let ts = u64::from_be_bytes(key[32..40].try_into().unwrap());
        if ts >= cutoff_ms {
            continue; // not expired yet — leave it, don't jump the cursor past it
        }
        to_delete.push(key.clone());
    }
    let mut next_cursor = last_key.to_vec();
    next_cursor.push(0); // sorts immediately after `last_key` itself
    (to_delete, Some(next_cursor))
}

/// Pure planning step for the DM retention reaper's Pass B: given a batch of
/// `DM_CONVERSATIONS` rows (keyed `wallet_address(variable, ≤70 bytes) ++
/// !timestamp_be(8) ++ conversation_id(32)`) and a cutoff, returns the keys
/// to delete and the next cursor. The wallet-address prefix is NOT
/// fixed-width (see `reap_dm_conversations`'s doc comment) — its length is
/// derived from `key.len() - 40`, never a hardcoded start offset.
fn plan_dm_conversations_reap(
    rows: &[(Vec<u8>, Vec<u8>)],
    cutoff_ms: u64,
    batch_limit: usize,
) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
    if rows.is_empty() {
        return (Vec::new(), None);
    }
    let mut to_delete = Vec::new();
    let mut last_key: &[u8] = &rows[0].0;
    for (key, _) in rows {
        // See the matching comment in `plan_dm_msg_shaped_reap` — `last_key`
        // must only advance to a row actually examined this iteration.
        if to_delete.len() >= batch_limit {
            break;
        }
        last_key = key;
        if key.len() <= 40 {
            continue; // defensive — malformed key
        }
        let wallet_len = key.len() - 40;
        let neg_ts = u64::from_be_bytes(key[wallet_len..wallet_len + 8].try_into().unwrap());
        let ts = !neg_ts; // key stores the bitwise complement of the timestamp
        if ts >= cutoff_ms {
            continue;
        }
        to_delete.push(key.clone());
    }
    let mut next_cursor = last_key.to_vec();
    next_cursor.push(0);
    (to_delete, Some(next_cursor))
}

/// Pure planning step for the periodic identity-staleness sweep (design
/// doc "Closing the Identity-Sync Coverage Gap" §2): given a batch of
/// `USERS` rows (keyed by wallet address), returns which wallets to
/// re-trigger an identity-sync pull for and the next cursor.
///
/// Unlike the DM reaper's `to_delete` list above, hitting `max_retriggers`
/// does NOT stop the scan early — every row in `rows` is still examined and
/// the cursor still advances to the true end of the batch. Scan cost
/// (`sweep_batch_size`, bounded by the caller's `rows` length) and request
/// cost (`max_retriggers`, bounded here) are deliberately independent
/// knobs: local RocksDB I/O is cheap and shouldn't stall cursor progress
/// just because a batch happened to contain more incomplete rows than the
/// per-tick outbound-request budget — that would let one incomplete-heavy
/// region of the table starve every wallet after it from ever being
/// scanned, not just re-triggered.
///
/// **Selection within the cap is RANDOM, not positional** (code-audit
/// finding, first round): a batch is a deterministic, stable window given a
/// stable table — head-first truncation (take the first `max_retriggers`
/// incomplete rows found) would select the SAME wallets on every wrap,
/// forever, and never even reach a genuinely-stale wallet sorting after
/// enough permanently-incomplete ones (e.g. on-chain-registered wallets
/// that never set a display name — common, and by construction always
/// "incomplete" under `profile_looks_incomplete_json`) in its own batch.
/// Shuffling means every incomplete row in the batch has an equal, nonzero
/// probability of being picked each pass, so expected time-to-retry is
/// finite regardless of how the table is populated.
fn plan_identity_staleness_sweep(
    rows: &[(Vec<u8>, Vec<u8>)],
    max_retriggers: usize,
) -> (Vec<String>, Option<Vec<u8>>) {
    if rows.is_empty() {
        return (Vec::new(), None);
    }
    let mut incomplete: Vec<String> = Vec::new();
    for (key, value) in rows {
        if !identity_sync::profile_looks_incomplete_json(value) {
            continue;
        }
        // Validated the same way a peer-supplied `request.wallet` would be
        // (code-audit finding) — a `USERS` key can arrive via snapshot
        // bootstrap from a peer, not only local writes, so it isn't
        // unconditionally trusted to already be a well-formed subject
        // before it's handed to `maybe_trigger_identity_sync` and sent to
        // 3 peers.
        match std::str::from_utf8(key) {
            Ok(s) if identity_sync::is_plausible_subject(s) => incomplete.push(s.to_string()),
            _ => continue,
        }
    }
    use rand::seq::SliceRandom;
    incomplete.shuffle(&mut rand::thread_rng());
    incomplete.truncate(max_retriggers);
    // rows is non-empty here (checked above), so .last() always succeeds.
    let mut next_cursor = rows.last().expect("rows non-empty").0.clone();
    next_cursor.push(0);
    (incomplete, Some(next_cursor))
}

/// The running network layer.
pub struct NetworkService {
    /// The libp2p swarm managing all protocols.
    swarm: Swarm<OgmaraBehaviour>,
    /// GossipSub topic manager.
    pub topics: TopicManager,
    /// Message router for validation pipeline.
    router: MessageRouter,
    /// Storage reference for sync operations.
    storage: Storage,
    /// Notification engine for mention detection and push delivery.
    notification_engine: Option<Arc<NotificationEngine>>,
    /// Shared peer count (read by API health endpoint).
    peer_count: Arc<AtomicU32>,
    /// Node identity for signing announcements.
    signing_key: ed25519_dalek::SigningKey,
    /// Node ID (Base58).
    node_id: String,
    /// Public API URL (if configured).
    public_url: Option<String>,
    /// Connected Ogmara peers (shared with API layer for /network/nodes).
    connected_peers: Arc<RwLock<HashMap<String, ConnectedPeerInfo>>>,
    /// Internal mapping: libp2p PeerId → Ogmara node_id (for removal on disconnect).
    peer_node_ids: HashMap<PeerId, String>,
    /// Shared network counters for metrics dashboard (spec 10-dashboard.md §6.2).
    counters: Arc<NetworkCounters>,
    /// Bootstrap node addresses (for periodic redial when peers are low).
    bootstrap_addrs: Vec<Multiaddr>,
    /// Peers queued for reconnection after disconnect (with backoff).
    reconnect_queue: Vec<ReconnectEntry>,
    /// Known peer addresses from Identify (PeerId → best known address).
    /// Used to reconnect after disconnect.
    known_peer_addrs: HashMap<PeerId, Multiaddr>,
    /// Shared snapshot cache — populated by the background cache-builder
    /// task in `Node::run`. `None` until the first build completes.
    snapshot_cache: SharedSnapshotCache,
    /// Whether this node advertises and answers snapshot requests
    /// (mirrors `config.snapshot.serve_enabled` at startup).
    snapshot_serve_enabled: bool,
    /// Concurrency limiter for outbound `SnapshotResponse::Chunk` sends.
    /// `try_acquire`d in `handle_snapshot_event` for `GetChunk`. Sized from
    /// `config.snapshot.serve_max_concurrent_requests`. Phase 1 — exists
    /// to bound the working-set even if a peer pipelines many GetChunks.
    snapshot_chunk_semaphore: Arc<tokio::sync::Semaphore>,
    /// Inbound channel for snapshot-client commands (Phase 2). The
    /// bootstrap task constructs `SnapshotRequest`s and sends them via
    /// this channel; we forward each to the swarm and stash a oneshot
    /// sender keyed by the libp2p `OutboundRequestId` so the matching
    /// response (or failure) is delivered back to the caller.
    snapshot_client_rx: tokio::sync::mpsc::UnboundedReceiver<SnapshotClientCommand>,
    /// Outstanding outbound snapshot requests awaiting a response.
    pending_snapshot_requests:
        HashMap<libp2p::request_response::OutboundRequestId, tokio::sync::oneshot::Sender<SnapshotClientResult>>,
    /// Successful-Identify counter (spec 13 §4.3 stall trigger).
    /// Incremented every time we accept an Identify::Received event
    /// from a peer with our network protocol. Shared with
    /// `sc_discovery::ScDiscovery::run` so its 60s post-startup check
    /// can detect total isolation (zero peers identified ⇒ tier 1 +
    /// tier 2 came up empty ⇒ fire SC fan-out).
    identify_success_count: Arc<AtomicU64>,
    /// Snapshot of peer IDs present in `PEER_DIRECTORY` at startup —
    /// used to classify Identify::Received events as `book` tier
    /// (spec 13 §4.1). Not updated after startup: peers persisted
    /// later in the session were not "from the book" on this startup,
    /// they came from whichever tier produced their first dial.
    startup_book_peer_ids: HashSet<PeerId>,
    /// Peer IDs extracted from `[network] bootstrap_nodes` config —
    /// used to classify Identify::Received events as `config` tier.
    config_peer_ids: HashSet<PeerId>,
    /// Peer IDs that `sc_discovery::ScDiscovery::persist_multiaddr`
    /// has written to `PEER_DIRECTORY` this session. Cross-task
    /// shared so the Identify handler can classify them as `sc` tier
    /// (spec 13 §4.1 / §4.3). Population happens in sc_discovery, so
    /// the lock is acquired only briefly (HashSet insert / contains).
    sc_added_peer_ids: Arc<RwLock<HashSet<PeerId>>>,
    /// Cumulative publish-failure counters, partitioned by
    /// `PublishError` variant (spec 10 §9.2, l2-node 0.46.6+). Shared
    /// with `AppState` so the `/admin/network/mesh-stats` endpoint
    /// reads live values without blocking the publish hot path.
    publish_failure_counters: mesh_stats::PublishFailureCounters,
    /// Shared mesh-state snapshot, refreshed by this task every
    /// `MESH_STATS_REFRESH_INTERVAL` (30s). Single writer (this
    /// task), many readers (admin endpoint, future dashboards).
    mesh_stats: mesh_stats::SharedMeshStats,
    /// Optional alert sender — `None` when `[alerts] enabled =
    /// false`. Used to fire the `publish_failed_insufficient_peers`
    /// alert when a publish hits `NoPeersSubscribedToTopic`. The
    /// cooldown engine deduplicates re-fires.
    alert_event_tx: Option<crate::notifications::alerts::AlertEventSender>,
    /// Snapshot of `[backfill]` (spec 1 §channel-history-reconciliation,
    /// l2-node 0.47.0+). Drives the cold-join trigger in
    /// `subscribe_channel` and the responder-side rate limits.
    backfill_config: crate::config::BackfillConfig,
    /// Server-side rate-limit state for inbound `ReconcileRequest`s.
    /// Bounded by `[backfill] server_max_concurrent_per_peer` and
    /// `server_max_concurrent_per_channel`.
    reconcile_limits: Arc<reconcile::ResponderLimits>,
    /// Rolling responder budget per `(peer, channel)` (l2-node 0.141.0):
    /// `[backfill] total_envelopes_cap` burst, refilled at
    /// `total_envelopes_refill_per_hour`. Applied through
    /// `reconcile_limits`.
    reconcile_budget: budget::Gcra,
    /// Requester-side attempt throttle per channel (l2-node 0.141.0) —
    /// gates `maybe_trigger_backfill` together with `channel_backfill_due`.
    /// In memory only (no entry == due). See `budget::AttemptThrottle`.
    reconcile_throttle: budget::AttemptThrottle<u64>,
    /// Outstanding outbound reconciliation requests, keyed by
    /// libp2p `OutboundRequestId`. Resolves to a `(peer_id,
    /// channel_id)` pair so the response handler can route the
    /// envelopes to the right channel and either request the next
    /// cursor batch or finish.
    pending_reconcile_requests: HashMap<
        libp2p::request_response::OutboundRequestId,
        ReconcilePending,
    >,
    /// Channel IDs with an in-flight (or just-decided-not-due)
    /// reconciliation session RIGHT NOW — a dedup/mutex-like guard, not a
    /// "ever triggered" ledger (rewritten 2026-09-30 alongside the
    /// completion-signal fix — see `storage::schema::cf::
    /// CHANNEL_BACKFILL_STATE`). Entries are inserted by
    /// `maybe_trigger_backfill` and removed once that channel's session
    /// concludes one way or another (not due, no candidates, natural
    /// completion, every give-up path) — see
    /// `release_reconcile_trigger_if_no_siblings`. This lets the same
    /// channel_id be re-evaluated many times across a single process
    /// lifetime (every `subscribe_channel` call, every periodic
    /// `retry_incomplete_channel_backfills` tick), which is what makes an
    /// incomplete channel keep getting retried without needing a restart.
    reconcile_triggered: HashSet<u64>,
    /// In-progress "pick the most complete first-page responder" windows
    /// (l2-node 0.137.0), keyed by channel_id. Seeded by
    /// `maybe_trigger_backfill` when a fresh (cursor: None) fanout is
    /// dispatched; finalized (winner chosen, losers never processed) once
    /// every candidate has answered or `reconcile_compare_interval` finds
    /// its deadline has passed. See `finalize_reconcile_comparison`.
    pending_reconcile_comparisons: HashMap<u64, ReconcileComparison>,
    /// When each channel last got a metadata FOLLOW-UP walk (l2-node
    /// 0.152.0, G7 — `finalize_reconcile_comparison`): at most one per
    /// `RECONCILE_META_FOLLOWUP_INTERVAL` per channel, so a large channel
    /// whose chat is in sync does not re-page its whole metadata on every
    /// hourly in-sync recheck. Bounded (`MAX_RECONCILE_META_FOLLOWUP_KEYS`).
    reconcile_meta_followup_at: HashMap<u64, Instant>,
    /// Where an unfinished metadata walk with a peer stopped (l2-node
    /// 0.152.0, round-1 audit W2), keyed `(channel, peer)`: the next walk
    /// with that peer continues there instead of from the start, so a
    /// channel whose metadata exceeds one session's budget still converges.
    /// In-memory, `RECONCILE_META_RESUME_TTL`, bounded
    /// (`MAX_RECONCILE_META_RESUME_KEYS`); removed when a walk reaches its end.
    reconcile_meta_resume: HashMap<(u64, PeerId), (reconcile::MetaCursor, Instant)>,
    /// Per-peer reconcile completeness tracking (l2-node 0.137.0) —
    /// in-memory only, never persisted, since completeness is a live
    /// property a peer can regain at any time. Updated by
    /// `finalize_reconcile_comparison`; consulted by `maybe_trigger_
    /// backfill`'s candidate selection to deprioritize (never exclude)
    /// a peer that's been meaningfully behind its siblings several
    /// times in a row.
    peer_reconcile_health: HashMap<PeerId, PeerReconcileHealth>,
    /// Server-side rate-limit state for inbound `sync::SyncRequest`s (audit
    /// final pre-mainnet W7). Reuses `reconcile::ResponderLimits` directly
    /// rather than a duplicate type — `SyncRequestType::ChannelMessages` is
    /// `(peer, channel_id)`-shaped, identical to `ReconcileRequest`'s key
    /// space, since both are per-channel content-fetch protocols.
    sync_limits: Arc<reconcile::ResponderLimits>,
    /// Outstanding outbound sync-protocol requests, keyed by libp2p
    /// `OutboundRequestId` → the `channel_id` the request was for. Used by
    /// the response handler as a smuggling defense (audit final
    /// pre-mainnet W7): a responder can't answer a `ChannelMessages`
    /// request for channel A with envelopes for channel B. No peer_id
    /// needed here (unlike `pending_reconcile_requests`) — `sync_channels_
    /// with_peer` dials one specific peer directly per channel, no
    /// fanout/racing to cancel.
    pending_sync_requests: HashMap<libp2p::request_response::OutboundRequestId, u64>,
    /// Server-side rate-limit state for inbound `IdentitySyncRequest`s,
    /// keyed by `(peer, wallet)` (P-1, l2-node 0.50.0+).
    identity_sync_limits: Arc<identity_sync::IdentityResponderLimits>,
    /// Rolling responder budget per `(peer, wallet)` for identity-sync
    /// (l2-node 0.151.0): `[identity_resync] responder_budget_burst`,
    /// refilled at `responder_budget_refill_per_hour`.
    identity_sync_budget: budget::Gcra,
    /// Outstanding outbound identity-sync requests, keyed by
    /// `OutboundRequestId` → `(peer, wallet, scopes)` so the response
    /// handler can apply + page the right wallet's bundle.
    pending_identity_sync_requests: HashMap<
        libp2p::request_response::OutboundRequestId,
        IdentitySyncPending,
    >,
    /// Wallets this node has triggered an identity-sync pull for at least
    /// once this process lifetime — dedups repeated first-seen triggers.
    /// Bounded via oldest-entry eviction (security-audit MEDIUM-2, mirrors
    /// `IdentityResponderLimits::add_served`'s W5 fix): a wholesale clear on
    /// overflow is attacker-triggerable now that the gossip-observed trigger
    /// feeds this set from free, attacker-mintable keypairs, and clearing it
    /// would reset the one-shot-per-session guarantee for every legitimate
    /// wallet at once. `identity_sync_triggered_order` tracks insertion order
    /// for eviction; the two must always be updated together.
    identity_sync_triggered: HashSet<String>,
    identity_sync_triggered_order: std::collections::VecDeque<String>,
    /// Server-side rate-limit state for inbound news-sync requests (P-3).
    news_sync_limits: Arc<news_sync::NewsResponderLimits>,
    /// Rolling responder budget per peer for news-sync (l2-node 0.151.0):
    /// `[backfill] news_responder_budget_burst`, refilled at
    /// `news_responder_budget_refill_per_hour`.
    news_sync_budget: budget::Gcra,
    /// Outstanding outbound news-sync requests → the peer they went to plus
    /// the requester-side paging budget (for race-cancel + paging; W9).
    pending_news_sync_requests: HashMap<
        libp2p::request_response::OutboundRequestId,
        NewsSyncPending,
    >,
    /// Set once the one-time global-news backfill has been fired this process
    /// lifetime (only fires when NEWS_FEED was empty and peers existed).
    /// When the last global-news reconciliation was started, or `None` if none
    /// has run in this process. Drives both the cold-join sync and the periodic
    /// catch-up (see `BackfillConfig::news_catchup_interval_hours`).
    last_news_sync: Option<std::time::Instant>,
    /// DM offline store-and-forward policy (spec 3, l2-node 0.69.0+): persistent
    /// DM-subscription cap + LRU, and the dm-sync backfill window.
    dm_config: crate::config::DmConfig,
    /// Identity-sync coverage-gap policy (design doc: "Closing the
    /// Identity-Sync Coverage Gap"): the broadened observed-author trigger
    /// (`handle_gossip_message`) and the periodic `USERS` staleness sweep
    /// (`sweep_identity_staleness`).
    identity_resync_config: crate::config::IdentityResyncConfig,
    /// Private-channel-sync policy (closes the F2 backfill gap, l2-node
    /// 0.138.0+): backfill window + periodic retry-sweep cadence/batch
    /// size. Mirrors `BackfillConfig`'s equivalent knobs.
    private_channel_sync_config: crate::config::PrivateChannelSyncConfig,
    /// Remaining observed-author identity-sync triggers this node may fire
    /// before the next `identity_staleness_interval` refill (security-audit
    /// finding: live gossip has no PoW gate and no per-wallet rate limit
    /// that bites a flood of distinct fresh keypairs, so this is the ONLY
    /// thing bounding that path's outbound request volume — see
    /// `IdentityResyncConfig::max_observed_triggers_per_interval`'s doc
    /// comment). Refilled to that config value at the top of every
    /// `sweep_identity_staleness` tick; decremented in
    /// `handle_gossip_message` each time the observed-author trigger
    /// actually fires. Starts at the full budget (not zero) so a
    /// freshly-started node isn't silently inert for its first interval.
    observed_trigger_budget: usize,
    /// The same per-interval budget for authors of BACKFILLED envelopes
    /// (G9, l2-node 0.151.0, audit N3) — separate so a large backfill cannot
    /// starve the live-gossip trigger (or the reverse). Sized and refilled
    /// like `observed_trigger_budget`
    /// (`[identity_resync] max_observed_triggers_per_interval`).
    backfill_author_trigger_budget: usize,
    /// Server-side rate-limit state for inbound dm-sync requests (Phase 2).
    dm_sync_limits: Arc<dm_sync::DmResponderLimits>,
    /// Rolling responder budget per peer for dm-sync (l2-node 0.151.0):
    /// `[dm] sync_responder_budget_burst`, refilled at
    /// `sync_responder_budget_refill_per_hour`.
    dm_sync_budget: budget::Gcra,
    /// Outstanding outbound dm-sync requests → `(peer, wallet)` for race-cancel
    /// + cursor paging of that wallet's backfill.
    pending_dm_sync_requests: HashMap<
        libp2p::request_response::OutboundRequestId,
        DmSyncPending,
    >,
    /// Fanout siblings of a dm-sync session cancelled when another peer
    /// answered first (l2-node 0.153.0, G4) → the wallet they were sent for.
    /// Their FIRST pages still arrive; only the order-independent head
    /// envelopes of those pages (`dm_sync::is_dm_sync_head_type`:
    /// `DeviceDelegation`, `KeyVaultSync`, `SettingsSync`, DM-scope
    /// `ChannelKeyEnvelope`) are applied — last-write-wins keeps the newest
    /// vault, so a fresh node ends up with the newest vault any of the
    /// fanout peers holds, not just the first responder's. Removed
    /// on response / failure; bounded by `MAX_DM_SYNC_CANCELLED_SIBLINGS`.
    dm_sync_cancelled_siblings: HashMap<libp2p::request_response::OutboundRequestId, String>,
    /// Wallets this node has triggered a dm-sync backfill for at least once this
    /// process lifetime — dedups repeated first-seen triggers (per auth).
    dm_backfill_triggered: HashSet<String>,
    /// Wallet → last wallet-signed dm-sync authorization claim received for
    /// it this session (audit W5). Populated by `maybe_trigger_dm_backfill`;
    /// consulted there AND by the pagination-continuation arm of
    /// `handle_dm_sync_event` (which doesn't go through
    /// `register_local_dm_user` again, so can't get a fresh one re-threaded
    /// through `DmSyncPending`). Fine to go stale — a later fanout attempt
    /// with a stale claim just fails `verify_wallet_claim` (safe degrade).
    /// Bounded/cleared the same way `dm_backfill_triggered` is.
    wallet_claims: HashMap<String, dm_sync::WalletAuthClaim>,
    /// Wallet → last time (ms) we persisted its `LOCAL_DM_USERS` row this
    /// session. Lets the per-REST-request registration path skip redundant
    /// RocksDB work, while still refreshing `last_active_ms` on a throttle so
    /// LRU eviction sees genuine recency (not just first-seen). An entry is
    /// REMOVED when the wallet is evicted, so a re-auth re-creates its row +
    /// subscription. Cleared on overflow. (The backfill trigger is gated
    /// separately so it still fires once peers exist.)
    local_dm_users_seen: HashMap<String, u64>,
    /// Server-side rate-limit state for inbound private-channel-sync
    /// requests (closes the F2 backfill gap, l2-node 0.138.0+).
    private_channel_sync_limits: Arc<private_channel_sync::PrivateChannelSyncResponderLimits>,
    /// Rolling responder budget per peer (l2-node 0.141.0):
    /// `[private_channel_sync] responder_budget_burst`, refilled at
    /// `responder_budget_refill_per_hour`.
    private_channel_sync_budget: budget::Gcra,
    /// Requester-side attempt throttle per `(wallet, channel_id)` (l2-node
    /// 0.141.0) — gates `maybe_trigger_private_channel_sync`.
    private_channel_sync_throttle: budget::AttemptThrottle<(String, u64)>,
    /// Node-wide bound on backfill responses being built off the event
    /// loop (`MAX_CONCURRENT_RESPONDER_BUILDS`, round 4).
    responder_build_permits: Arc<tokio::sync::Semaphore>,
    /// Node-wide bound on continuation requests waiting for a build slot
    /// (`MAX_CONTINUATION_BUILD_WAITERS`, round-5 C-W1).
    continuation_wait_permits: Arc<tokio::sync::Semaphore>,
    /// Off-loop builds hand their finished response back here; `run()`
    /// takes the receiver and sends each response on the swarm.
    deferred_response_tx: tokio::sync::mpsc::UnboundedSender<DeferredResponse>,
    /// Receiver half of `deferred_response_tx`, taken by `run()`.
    deferred_response_rx: Option<tokio::sync::mpsc::UnboundedReceiver<DeferredResponse>>,
    /// Outstanding outbound private-channel-sync requests → pending state
    /// for race-cancel + cursor paging of that (wallet, channel) pair's
    /// backfill. See `DmSyncPending`'s doc comment for the paging-budget
    /// fields' rationale (audit final pre-mainnet W9) — mirrored here.
    pending_private_channel_sync_requests: HashMap<
        libp2p::request_response::OutboundRequestId,
        PrivateChannelSyncPending,
    >,
    /// `(wallet, channel_id)` pairs this node has triggered a
    /// private-channel backfill for at least once this process lifetime —
    /// dedups repeated first-seen triggers. Mirrors `dm_backfill_triggered`.
    private_channel_sync_triggered: HashSet<(String, u64)>,
    /// Wallet → last wallet-signed private-channel-sync authorization claim
    /// received for it this session. Mirrors `wallet_claims` (dm_sync)
    /// exactly, but a SEPARATE map with a SEPARATE claim type — the two
    /// protocols' domain-separated signed strings mean a dm-sync claim can
    /// never verify here and vice versa; keeping distinct maps avoids any
    /// accidental cross-use.
    private_channel_sync_wallet_claims: HashMap<String, private_channel_sync::WalletAuthClaim>,
    /// Private channels whose gossip topic this node deliberately does NOT
    /// hold because their `PRIVATE_CHANNEL_LIFECYCLE` row says no local
    /// member is left (l2-node 0.149.0). Only channels in this set are ever
    /// re-subscribed by `reconcile_channel_lifecycle`; everything else keeps
    /// the existing subscribe paths.
    lifecycle_unsubscribed: HashSet<u64>,
    /// Receiver of `Storage`'s lifecycle notifier (a channel id whose
    /// lifecycle row was written or removed by ANY ingress path — API, WS,
    /// gossip, sync, scanner). Taken by `run()`.
    lifecycle_rx: Option<tokio::sync::mpsc::UnboundedReceiver<u64>>,
    /// How many times the private-sync no-host gate walked gossipsub's
    /// `all_peers()` (`remote_subscribed_topics`) — lets tests assert one
    /// walk per claim refresh / sweep tick, not one per channel.
    remote_subscriber_walks: u64,
    /// `[private_channels] lifecycle_check_interval_secs` — cadence of the
    /// backstop pass (`lifecycle_backstop`).
    lifecycle_check_interval_secs: u64,
    /// Channel ids notified by the storage layer (or whose unsubscribe was
    /// deferred) since the last backstop tick — re-applied by that tick.
    lifecycle_dirty: HashSet<u64>,
    /// Rotating position (channel id) of the backstop tick's batch over
    /// `lifecycle_unsubscribed`; `0` = from the smallest id.
    lifecycle_unsub_cursor: u64,
    /// Rotating cursor (raw `PRIVATE_CHANNEL_LIFECYCLE` key) of the
    /// background page scan that converges missed rows and maintains the
    /// pending gauge. Empty = from the start.
    lifecycle_scan_cursor: Vec<u8>,
    /// Pending rows counted so far in the current scan rotation; published
    /// to the `private_channels_pending` gauge when the rotation completes.
    lifecycle_scan_pending: u64,
    /// A page read is running on the blocking pool (one at a time).
    lifecycle_scan_in_flight: bool,
    /// Finished page reads come back here (sender cloned into the blocking
    /// task; receiver taken by `run()`).
    lifecycle_scan_tx: tokio::sync::mpsc::UnboundedSender<LifecycleScanPage>,
    lifecycle_scan_rx: Option<tokio::sync::mpsc::UnboundedReceiver<LifecycleScanPage>>,
    /// Presence-gossip manager (spec 13 §10, l2-node 0.48.0+). `Some`
    /// iff `[network.presence] enabled = true` at startup; held in an
    /// `Arc` so the cache + rate limiter can be shared with the REST
    /// handlers and the background sweep task without re-spawning.
    presence_manager: Option<Arc<presence::PresenceManager>>,
    /// Hash of the presence topic, cached so the gossipsub Message
    /// handler can dispatch on it without re-hashing each time. `None`
    /// iff `presence_manager` is `None`.
    presence_topic_hash: Option<libp2p::gossipsub::TopicHash>,
    /// Hot Topics mesh aggregator (spec 3 §3.9, l2-node 0.124.0+). Always
    /// present; a no-op when `[hot_topics] enabled = false`. Shared (`Arc`)
    /// with the REST layer so `GET /api/v1/news/hot-topics` reads the same
    /// merged view this service folds inbound digests into.
    hot_topics: Arc<hot_topics::HotTopicsAggregator>,
    /// Hash of the `/network` topic — used to route inbound `HotTopicsDigest`
    /// gossip to the aggregator before the generic envelope router.
    network_topic_hash: libp2p::gossipsub::TopicHash,
    /// libp2p keypair clone, kept for signing outbound Hot Topics digests
    /// (protocol §3.15 — digests are signed with the node's libp2p key,
    /// verified via the key embedded in `peer_id`).
    hot_topics_keypair: libp2p::identity::Keypair,
    /// True once the self-broadcast has fired on mesh stabilization
    /// (≥ 3 connected peers — spec 13 §10.5). One-shot per process so
    /// the steady-state interval handles all subsequent broadcasts.
    presence_initial_broadcast_done: bool,
    /// Channel that carries presence-record validation outcomes from
    /// the spawned verifier task back into the swarm event loop, where
    /// `gossipsub.report_message_validation_result(...)` is called.
    /// Required because `.validate_messages()` is enabled on the
    /// gossipsub config (spec 13 §10.3) — libp2p will hold relay until
    /// we report Accept/Reject/Ignore for each received message.
    /// `None` iff the presence subsystem is disabled.
    presence_validation_tx:
        Option<tokio::sync::mpsc::UnboundedSender<PresenceValidationOutcome>>,
    /// Drain side of the above. Held by the swarm event loop in `run`.
    /// Wrapped in `Option` because `run` takes the receiver out at
    /// startup; field is `None` after that.
    presence_validation_rx:
        Option<tokio::sync::mpsc::UnboundedReceiver<PresenceValidationOutcome>>,
    /// Bounds concurrent inbound presence-record verifications (audit
    /// 2026-06-07 W5). Each presence gossip message spawns an Ed25519 verify;
    /// without a cap, a peer flooding the presence topic could spawn unbounded
    /// tasks → CPU/memory exhaustion. When no permit is free the message is
    /// reported `Ignore` (dropped, not verified) instead of spawning.
    presence_verify_sem: Arc<tokio::sync::Semaphore>,
    /// Per-peer sliding-window message counter for non-presence gossip
    /// (audit final pre-mainnet W10, l2-node 0.100.0). Checked in
    /// `handle_swarm_event` BEFORE `handle_gossip_message` runs, so a
    /// flooding peer's messages are dropped without paying the
    /// Keccak/Ed25519/storage cost — mirrors `presence_verify_sem`'s
    /// "gate before expensive work" shape, but as a rate limit (many
    /// messages/sec are legitimate on chat/news topics) rather than a
    /// concurrency cap. Single-owner field (only touched from
    /// `handle_swarm_event`/`handle_gossip_message`, both `&mut self`
    /// on this task) — no lock needed, unlike `PresenceRateLimiter`
    /// which is shared with spawned async verifier tasks.
    gossip_rate_limiter: HashMap<PeerId, GossipRateWindow>,
    /// Per-peer application-controlled gossipsub score (P5), driven by
    /// `handle_gossip_message`'s existing `RouteResult` classification
    /// (audit final pre-mainnet W10). Raw tracked value pushed to
    /// gossipsub via `set_application_score`; NOT the same number as
    /// the peer's overall gossipsub score (which also folds in P6/P7
    /// and the configured `app_specific_weight`). Pruned by staleness
    /// (`GossipAppScoreEntry::last_touched`), not just by value —
    /// Security Audit (W10 follow-up): a value-only prune (drop iff
    /// `== 0`) left a permanent entry for any peer that connects once,
    /// sends a single `Invalid` message, and disconnects forever,
    /// letting a slow one-shot-PeerId Sybil campaign grow this map
    /// without bound (cheap: a new keypair is free, and each such peer
    /// self-prunes out of `gossip_rate_limiter` on the very next sweep,
    /// so the rate-limiter's soft cap never engages to stop it either).
    gossip_app_score: HashMap<PeerId, GossipAppScoreEntry>,
    /// Per-peer live-connection direction counts, keyed by libp2p
    /// `PeerId`. Maintained from `ConnectionEstablished` /
    /// `ConnectionClosed` (`endpoint.is_dialer()` gives the direction).
    /// Read by `refresh_mesh_stats` to populate the B4 peer-telemetry
    /// view (`/admin/network/peer-telemetry`, l2-node 0.48.4). Tuple is
    /// `(outbound, inbound)`. Entries are removed when both reach zero.
    peer_directions: HashMap<PeerId, (u32, u32)>,
}

/// A request to publish an envelope to a GossipSub topic, sent from the
/// API layer to the network task over `gossip_tx`.
///
/// `respond_to` lets a client-facing handler learn the publish outcome
/// (B4 fix proper, l2-node 0.48.4). The message is *already persisted*
/// by `MessageRouter::process_message` before it reaches this channel,
/// so a degraded real-time publish is not data loss — channel-history
/// reconciliation (B1) carries it to peers that join later. Surfacing
/// the outcome just lets the UI distinguish "delivered to the mesh now"
/// from "stored, will propagate via backfill".
pub struct GossipPublish {
    /// Topic string (e.g. `/ogmara/mainnet/v1/channel/42`).
    pub topic: String,
    /// Serialized envelope bytes to publish.
    pub data: Vec<u8>,
    /// When `Some`, the network task reports the publish outcome here.
    /// `None` for best-effort internal re-publishes (e.g. the
    /// `DeviceDelegation` relay) where no caller is awaiting a result.
    pub respond_to: Option<tokio::sync::oneshot::Sender<PublishOutcome>>,
}

/// Outcome of a single GossipSub publish, reported back to the API
/// caller via [`GossipPublish::respond_to`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Handed to gossipsub for at least one mesh peer.
    Propagated,
    /// Publish failed (typically `NoPeersSubscribedToTopic`): no mesh
    /// peer was available right now. The message is persisted locally
    /// and will reach peers via backfill/reconciliation or once the
    /// mesh forms — this is *degraded real-time delivery*, not loss.
    Degraded,
}

/// Spec 13 §10.3 validation outcome carried from the spawned verifier
/// task back to the swarm event loop. The loop translates this into a
/// libp2p `MessageAcceptance` and reports it to gossipsub so relay is
/// either allowed or suppressed.
#[derive(Debug)]
struct PresenceValidationOutcome {
    message_id: libp2p::gossipsub::MessageId,
    propagation_source: PeerId,
    acceptance: libp2p::gossipsub::MessageAcceptance,
}

/// Per-pending-outbound-reconciliation state.
#[derive(Debug, Clone)]
struct ReconcilePending {
    peer_id: PeerId,
    channel_id: u64,
    /// Requester-side paging budget state (audit final pre-mainnet W9).
    /// `0`/`0` on the session's first request; threaded forward and
    /// incremented on each subsequent page. See
    /// `MAX_PAGES_PER_SESSION`/`MAX_CONSECUTIVE_UNPRODUCTIVE_PAGES`.
    pages_fetched: u32,
    consecutive_unproductive_pages: u32,
    /// Cumulative envelopes with `RouteResult::Accepted` — genuinely NEW,
    /// signature-verified content — across every page of this session.
    /// Threaded forward across pages so a genuine multi-page session
    /// accumulates correctly; gates `mark_channel_backfill_complete` and
    /// sibling-cancellation.
    ///
    /// Security-audit findings (2026-09-30, two rounds): a page reporting
    /// `has_more = false` is NOT itself proof the responder had (or sent)
    /// any real data. Round 1: an attacker can win the fanout race with
    /// an instant, trivially-cheap all-garbage response that fails router
    /// validation. Round 2: counting `RouteResult::Duplicate` toward this
    /// (as round 1's fix did) is ALSO forgeable near-for-free — the
    /// router's duplicate check (`Storage::message_exists`) runs BEFORE
    /// msg_id-binding and signature verification and is keyed globally,
    /// not per-channel, so an attacker can pair any msg_id that already
    /// exists ANYWHERE on this node (trivially obtained by posting one
    /// message themselves, in any channel) with a forged envelope
    /// claiming this channel and an unchecked signature, and it
    /// short-circuits straight to `Duplicate`. Only `Accepted` requires a
    /// real Ed25519 signature over the claimed content, matching the
    /// existing precedent in this file's `sync` protocol response
    /// handler, which already excludes `Duplicate` from its own progress
    /// counter for the same reason.
    ///
    /// Accepted residual (round-3 security audit, 2026-09-30; scope
    /// corrected round 4): a fresh, unregistered Ed25519 keypair can sign
    /// ONE trivial `ChatMessage` targeting a genuinely open Public
    /// channel (`channel_type == 0` ONLY — `check_readonly_channel`
    /// already gates ReadPublic/`channel_type == 1` to the creator or a
    /// moderator, so this does NOT reach `Accepted` there) with no PoW
    /// and no rate limit (`process_synced_message` is deliberately
    /// exempt for the sync/backfill path) and reach `Accepted` for
    /// near-zero cost, which — as the sole peer left
    /// after sibling cancellation — unilaterally asserts completion with
    /// fabricated content. This is NOT merely "a peer's own view might be
    /// stale" (the framing this comment used before the round-3 audit);
    /// it is "any single race-winning peer can single-handedly fabricate
    /// completion," genuinely comparable in cost to the round-1/round-2
    /// bugs this file just spent two rounds closing. What changed for the
    /// better: false completion is no longer PERMANENT — it expires
    /// after `channel_catchup_interval_hours` (default 6h), so an
    /// attacker must keep re-winning the race every cycle rather than
    /// masking history once and forever. l2-node 0.137.0 adds the cheaper
    /// interim hardening floated here — compare every fanout candidate's
    /// first page instead of trusting whichever answers first, and track
    /// per-peer staleness (see `ReconcileComparison`/`PeerReconcileHealth`
    /// below) — which makes a single peer's fabricated response need to
    /// out-report every honest sibling to win, not merely answer fastest.
    /// It is still not the full spec-14 fingerprint/epoch-root proof:
    /// a peer that's ahead of its siblings (including a colluding one)
    /// can still win and assert completion. Recorded here so neither gap
    /// is mistaken for fully closed.
    total_accepted: u64,
    /// Metadata paging of this session (l2-node 0.152.0, G7).
    meta: ReconcileMetaState,
}

/// Metadata paging state of one reconcile session (l2-node 0.152.0, G7).
///
/// **When a channel counts COMPLETE** (`mark_channel_backfill_complete`):
/// its chat pages ended naturally (`has_more == false`) AND — when the
/// session's first page reported `meta_truncated` — the metadata walk with
/// the same peer reached its end too (a metadata page with
/// `meta_truncated == false`), AND the session accepted at least one
/// genuinely new envelope (chat or metadata, strictly `Accepted`). A walk
/// that stops early (capped, failed, a non-advancing cursor, the page
/// backstop) never marks complete; it reports "accepted but incomplete"
/// (retry soon) since its chat phase admitted something.
///
/// A metadata FOLLOW-UP walk (`MetaWalk::followup`, started after a
/// comparison with no winner whose candidate offered only verified
/// duplicates) is purely additive: it NEVER marks the channel complete and
/// never moves the attempt throttle — the comparison's own verdict
/// (in-sync recheck, or the dispatch backoff) stands. So metadata paging
/// can neither turn an in-sync channel into a retry loop nor fake
/// completion; its cost is bounded per channel by
/// `RECONCILE_META_FOLLOWUP_INTERVAL`.
#[derive(Debug, Clone, Default)]
struct ReconcileMetaState {
    /// The session's first page reported `meta_truncated`.
    truncated: bool,
    /// Where the first page's chronological metadata prefix ended (its
    /// `meta_next_cursor`, round-1 audit B2): the in-session walk continues
    /// from here, never from the start.
    prefix_end: Option<reconcile::MetaCursor>,
    /// `Some` while the session walks metadata pages.
    walk: Option<MetaWalk>,
}

/// An in-progress metadata walk (G7).
#[derive(Debug, Clone)]
struct MetaWalk {
    /// The cursor of the last metadata request; the next must be strictly
    /// greater (a hostile responder cannot loop the walk).
    last_cursor: reconcile::MetaCursor,
    /// Metadata pages received so far (`MAX_RECONCILE_META_PAGES`).
    pages: u32,
    /// A follow-up walk (see `ReconcileMetaState`).
    followup: bool,
}

/// Max metadata pages one reconcile metadata walk follows (l2-node
/// 0.152.0) — same bound as private-channel sync's metadata phase.
const MAX_RECONCILE_META_PAGES: u32 = private_channel_sync::MAX_META_PAGES_PER_SESSION;

/// Minimum spacing of metadata FOLLOW-UP walks per channel (l2-node
/// 0.152.0, G7) — the default `channel_catchup_interval_hours`.
const RECONCILE_META_FOLLOWUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 3600);

/// Bound on `NetworkService::reconcile_meta_followup_at`. When full (after
/// dropping expired entries) no new follow-up is started (fail closed: the
/// metadata is still delivered by any session that admits chat).
const MAX_RECONCILE_META_FOLLOWUP_KEYS: usize = 100_000;

/// How long an unfinished walk's resume position is kept (l2-node 0.152.0,
/// round-1 audit W2).
const RECONCILE_META_RESUME_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Bound on `NetworkService::reconcile_meta_resume`; at the cap expired
/// entries are dropped first, and if still full the position is not kept
/// (the next walk restarts from its usual start — slower, never wrong).
const MAX_RECONCILE_META_RESUME_KEYS: usize = 100_000;

/// A live comparison window for one channel's freshly-triggered (`cursor:
/// None`) fanout — l2-node 0.137.0. Exists only between
/// `maybe_trigger_backfill` dispatching the initial requests and
/// `finalize_reconcile_comparison` resolving them; a continuation page
/// (`cursor: Some(_)`) never creates or consults one, since by then a
/// winner is already committed and normal single-peer paging applies.
#[derive(Debug)]
struct ReconcileComparison {
    /// request_ids still awaiting a `Response` or `OutboundFailure`.
    /// Finalizes early (§`reconcile_compare_interval`) once this is
    /// empty, without waiting for `deadline`.
    outstanding: HashSet<libp2p::request_response::OutboundRequestId>,
    /// `(peer, response)` for every candidate that answered with
    /// something informative (not `server_capped`, not empty-with-no-
    /// more) — ranked by `rank_reconcile_candidates_by_size` at finalize
    /// time. A peer that answered uninformatively simply never appears
    /// here, same treatment as one that failed outright.
    candidates: Vec<(PeerId, reconcile::ReconcileResponse)>,
    /// Wall-clock deadline for finalizing even if `outstanding` isn't
    /// empty yet — bounds one slow/dead candidate's worst-case delay to
    /// `RECONCILE_COMPARE_WINDOW`, well under the protocol's 45s request
    /// timeout (`network::behaviour`).
    deadline: Instant,
    /// Some candidate answered `server_capped` (l2-node 0.141.0): it may
    /// hold content we lack, so the comparison can never conclude IN_SYNC
    /// (`comparison_in_sync`).
    any_capped: bool,
}

/// Per-peer reconcile completeness tracking (l2-node 0.137.0) — in-memory
/// only, deliberately never persisted (see `NetworkService::
/// peer_reconcile_health`'s doc comment for why). `consecutive_losses`
/// is a soft, freely-resettable signal, never a security control on its
/// own (staleness only ever deprioritizes fanout selection, never
/// excludes or authorizes anything) — so pruning this entry early under
/// memory pressure (see `PEER_RECONCILE_HEALTH_MAX_IDLE`) just means
/// this peer resets to "not stale" and gets an earlier-than-scheduled
/// courtesy reprobe, never a correctness or security issue.
#[derive(Debug, Clone)]
struct PeerReconcileHealth {
    /// Consecutive comparisons (against DIFFERENT channels/triggers, not
    /// re-counted for the same one) where this peer was TRIED and
    /// verified to yield zero real progress while a later candidate in
    /// the SAME comparison proved real content existed — see
    /// `finalize_reconcile_comparison`'s doc comment for why this must
    /// be scored from verified trial outcomes, never raw reported
    /// counts. Reset to 0 the moment this peer wins a comparison again —
    /// a genuinely-recovered peer sheds the flag automatically, no
    /// separate "unflag" step.
    consecutive_losses: u32,
    /// Last time a currently-stale peer was deliberately given an extra,
    /// above-`fanout` probe chance (see `maybe_trigger_backfill`'s
    /// candidate selection) to requalify. `None` means never probed —
    /// probe immediately next opportunity.
    last_probed_at: Option<Instant>,
    /// Last time this entry was touched at all (a comparison result or
    /// a reprobe stamp) — staleness-based prune key, mirroring
    /// `gossip_app_score`'s `last_touched`/W10 pattern (a value-only
    /// prune left an exploitable gap there — see that field's doc
    /// comment). Security-audit finding (2026-09-30, round 1): this map
    /// previously had no cap or prune at all, an unbounded-growth Sybil
    /// vector identical to one this file already closed once for
    /// `gossip_rate_limiter`/`gossip_app_score`.
    last_touched: Instant,
}

/// Outcome of `NetworkService::apply_reconcile_response` for one
/// candidate. `Handled` means the call already took every appropriate
/// terminal action for this session (continuation, completion, or a
/// give-up that already released `reconcile_triggered`) — the caller has
/// nothing left to do. `NoProgress` means this specific response yielded
/// zero verified progress and did NOT touch `reconcile_triggered` —
/// reserved for the comparison-trial loop (`finalize_reconcile_
/// comparison`), which tries ranked candidates one at a time and must
/// decide for itself whether to try the next one or, having exhausted
/// them all, release the dedup guard exactly once (releasing it after
/// EVERY failed trial would let a later trial's dispatch race a
/// concurrent re-trigger for the same channel).
///
/// `NoProgress { verified_in_sync }` (l2-node 0.141.0): `true` only for a
/// comparison trial whose FIRST page ended the session (`has_more ==
/// false`) and consisted entirely of byte-verified duplicates
/// (`ReconcileTally::is_verified_in_sync_page`) — evidence that THIS peer
/// offered nothing new, used only for the attempt throttle
/// (`comparison_in_sync`), never for completion.
///
/// `meta_followup` (l2-node 0.152.0, G7): `true` only for a comparison
/// trial's first page that reported `meta_truncated` and carried nothing
/// but byte-verified duplicates (`ReconcileTally::is_verified_dup_page`,
/// `has_more` not considered) — this peer demonstrably holds what we hold,
/// so after a no-winner comparison it may serve a metadata follow-up walk.
enum ReconcileApplyOutcome {
    Handled,
    NoProgress { verified_in_sync: bool, meta_followup: bool },
}

/// How one reconcile page fared when routed by the requester (l2-node
/// 0.141.0, extracted from `apply_reconcile_response` so the in-sync
/// evidence is unit-testable).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ReconcileTally {
    /// `Accepted` + `Duplicate` (the "won the race" count).
    admitted: usize,
    /// Strictly `Accepted` — genuinely new, signature-verified content.
    newly_accepted: usize,
    /// `Duplicate`s byte-identical to the stored copy
    /// (`duplicate_is_verified`).
    verified_dups: usize,
    /// Envelopes dropped by the cross-channel smuggling check.
    cross_channel_dropped: usize,
    /// Anything that is not clean evidence: a dropped, rejected, invalid
    /// or PoW-gated envelope, a `Duplicate` that is NOT byte-identical (a
    /// forged envelope reusing a known msg_id), or an oversized page.
    tainted: bool,
    /// GDPR `DeletionRequest`s that carry no evidence either way (l2-node
    /// 0.151.0, audit W1/W4): one accepted only as a PENDING row (its target
    /// is withheld), or one this node refused (outside its window, wrong
    /// scope, author skew, at capacity). Neither progress nor taint.
    ignored_deletions: usize,
    /// Envelopes refused because their author is banned / muted in the
    /// channel, or reactions whose target is not stored (l2-node 0.152.0,
    /// `router::is_neutral_sync_refusal`): an honest responder legitimately
    /// holds pre-ban / pre-mute history this node refuses, and reactions to
    /// targets outside this node's window. Neither progress nor taint.
    ignored_moderation: usize,
}

impl ReconcileTally {
    /// The page proves THIS responder offered nothing new: it is the whole
    /// session (`has_more == false`), non-empty, untainted, and every
    /// envelope on it is a byte-verified duplicate.
    fn is_verified_in_sync_page(&self, env_count: usize, has_more: bool) -> bool {
        !has_more && self.is_verified_dup_page(env_count)
    }

    /// The page is non-empty, untainted, and every envelope on it is a
    /// byte-verified duplicate (or an ignorable deletion request) — whether
    /// or not more pages follow (l2-node 0.152.0, G7 follow-up gate).
    fn is_verified_dup_page(&self, env_count: usize) -> bool {
        env_count > 0
            && !self.tainted
            && self.newly_accepted == 0
            && self.verified_dups > 0
            && self.verified_dups + self.ignored_deletions + self.ignored_moderation == env_count
    }
}

/// Route one reconcile page's envelopes through the requester's router,
/// in order (l2-node 0.141.0 extraction — the logic is the 0.136/0.137
/// loop plus the in-sync evidence). A page larger than `max_page_size` is
/// not verified at all (tainted, unproductive).
fn tally_reconcile_envelopes(
    router: &MessageRouter,
    storage: &Storage,
    peer: &PeerId,
    channel_id: u64,
    envelopes: &[Vec<u8>],
    max_page_size: usize,
    deletion_min_ts_ms: u64,
    accepted_authors: &mut Vec<(String, u8)>,
) -> ReconcileTally {
    let mut t = ReconcileTally::default();
    if envelopes.len() > max_page_size {
        // Security-audit follow-up on W9: see identity-sync's arm for the
        // full rationale — refuse to verify ANY envelope in a page that
        // exceeds this node's OWN configured max page size, treating it as
        // unproductive rather than paying the verification cost.
        warn!(
            peer = %peer,
            channel_id,
            received = envelopes.len(),
            expected_max = max_page_size,
            "reconcile: response exceeds this node's own max page size; refusing to verify, treating as unproductive"
        );
        t.tainted = true;
        return t;
    }
    for env_bytes in envelopes {
        // Security Audit W1 (0.47.0): cross-channel smuggling defense.
        // The responder could otherwise stuff envelopes for channel B
        // into a response we sent for channel A; signatures verify (the
        // original authors really signed them) so the router would
        // happily index them under B. Reject any envelope whose
        // payload-extracted channel_id does not equal the channel we
        // asked for, BEFORE handing it to the router.
        let is_deletion = is_deletion_request(env_bytes);
        if !envelope_targets_channel(env_bytes, channel_id) {
            t.cross_channel_dropped += 1;
            t.tainted = true;
            continue;
        }
        match deletion_request_fit(storage, env_bytes, DeletionScope::Channel(channel_id), deletion_min_ts_ms) {
            DeletionFit::Fits => {}
            // A well-formed request this sync does not take is not evidence
            // against the peer (W4: windows differ per node).
            DeletionFit::Neutral => {
                t.ignored_deletions += 1;
                continue;
            }
            DeletionFit::Malformed => {
                t.cross_channel_dropped += 1;
                t.tainted = true;
                continue;
            }
        }
        match router.process_synced_message(env_bytes) {
            RouteResult::Accepted { .. } if is_deletion && pending_only_deletion(storage, env_bytes) => {
                // W1: accepted only as a pending row — not progress.
                t.ignored_deletions += 1;
            }
            RouteResult::Rejected(_) if is_deletion => {
                // W4: a 0x50 the router refuses by POLICY (target author skew,
                // too old, pending capacity) must not taint the page forever.
                // An `Invalid` one (bad signature / msg_id) still taints.
                t.ignored_deletions += 1;
            }
            RouteResult::Rejected(ref reason) if crate::messages::router::is_neutral_sync_refusal(reason) => {
                // l2-node 0.152.0 (B1): a banned / muted author's envelope
                // this node refuses is not evidence against the peer.
                t.ignored_moderation += 1;
            }
            RouteResult::Accepted { author, msg_type, .. } => {
                t.admitted += 1;
                t.newly_accepted += 1;
                // G9 (l2-node 0.151.0): sampled for the identity-pull gate.
                note_backfilled_author(accepted_authors, author, msg_type as u8);
            }
            RouteResult::Duplicate => {
                // Counted toward `admitted` but deliberately NOT toward
                // `newly_accepted`: the router's duplicate check runs
                // before signature verification and is keyed globally by
                // msg_id (security-audit 2026-09-30 round 2, see
                // `ReconcilePending::total_accepted`). For the in-sync
                // evidence it counts only when byte-identical to the
                // stored, ingest-verified copy.
                t.admitted += 1;
                if duplicate_is_verified(storage, env_bytes) {
                    t.verified_dups += 1;
                } else {
                    t.tainted = true;
                }
            }
            RouteResult::Rejected(reason) | RouteResult::Invalid(reason) => {
                t.tainted = true;
                warn!(
                    peer = %peer,
                    channel_id,
                    reason = %reason,
                    "reconcile: peer envelope rejected by router"
                );
            }
            RouteResult::PowRequired { .. } => {
                // Sync messages are PoW-exempt — should not fire.
                t.tainted = true;
            }
            // Key-epoch arbitration loss (l2-node 0.143.0) — treated like a
            // policy rejection on the sync path.
            RouteResult::KeyConflict(info) => {
                t.tainted = true;
                debug!(peer = %peer, channel_id, epoch = info.epoch, "reconcile: key envelope lost arbitration");
            }
        }
    }
    t
}

/// The IN_SYNC verdict for a comparison that found NO winner (l2-node
/// 0.141.0). All must hold: no dispatched candidate is still outstanding
/// at finalize (`all_answered` — not the deadline path; a candidate whose
/// request FAILED also leaves `outstanding`, so an unreachable peer does
/// not block IN_SYNC — it only delays a repair by one recheck); no candidate
/// answered `server_capped` (it may hold what we lack); at least one
/// candidate was tried; EVERY tried candidate proved a verified in-sync
/// first page (so a trial rejected under the has-more/zero-progress rule,
/// an oversized page, or a forged duplicate blocks it); and at least one
/// such candidate is not flagged stale. IN_SYNC only moves the attempt
/// throttle; it never writes the completion CF and never touches peer
/// health.
fn comparison_in_sync(
    all_answered: bool,
    any_capped: bool,
    trials: &[(PeerId, bool)],
    is_stale: impl Fn(&PeerId) -> bool,
) -> bool {
    all_answered
        && !any_capped
        && !trials.is_empty()
        && trials.iter().all(|(_, in_sync)| *in_sync)
        && trials.iter().any(|(p, _)| !is_stale(p))
}

/// Per-pending-outbound-identity-sync state (P-1).
#[derive(Debug, Clone)]
struct IdentitySyncPending {
    peer_id: PeerId,
    wallet: String,
    scopes: u8,
    /// See `ReconcilePending`'s doc comment (audit final pre-mainnet W9).
    pages_fetched: u32,
    consecutive_unproductive_pages: u32,
}

/// Per-pending-outbound-dm-sync state (offline store-and-forward Phase 2).
#[derive(Debug, Clone)]
struct DmSyncPending {
    peer_id: PeerId,
    wallet: String,
    /// See `ReconcilePending`'s doc comment (audit final pre-mainnet W9).
    pages_fetched: u32,
    consecutive_unproductive_pages: u32,
}

/// Lifecycle rows read per backstop page (`NetworkService::
/// start_lifecycle_scan_page`, l2-node 0.149.0).
const LIFECYCLE_BACKSTOP_PAGE: usize = 1024;

/// One finished backstop page read: `(ids with "is pending", next cursor)`
/// as returned by `Storage::private_channel_lifecycle_page`, or the error.
struct LifecycleScanPage {
    result: Result<(Vec<(u64, bool)>, Option<Vec<u8>>), String>,
}

/// Delivers exactly one `LifecycleScanPage` for a backstop page read: the
/// real one via `send`, or — if the blocking task panics or is dropped
/// before it ran — an `Err` page from `Drop`, so `lifecycle_scan_in_flight`
/// is always cleared and the backstop never stops scanning.
struct LifecycleScanSendGuard(Option<tokio::sync::mpsc::UnboundedSender<LifecycleScanPage>>);

impl LifecycleScanSendGuard {
    fn send(&mut self, page: LifecycleScanPage) {
        if let Some(tx) = self.0.take() {
            // The loop may be shutting down (receiver gone).
            let _ = tx.send(page);
        }
    }
}

impl Drop for LifecycleScanSendGuard {
    fn drop(&mut self) {
        self.send(LifecycleScanPage { result: Err("backstop page read did not complete".into()) });
    }
}

/// Per-pending-outbound-private-channel-sync state (closes the F2 backfill
/// gap). Keyed by `(wallet, channel_id)` rather than just `wallet` (dm_sync)
/// since one wallet can be independently backfilling several channels.
#[derive(Debug, Clone)]
struct PrivateChannelSyncPending {
    peer_id: PeerId,
    wallet: String,
    channel_id: u64,
    /// Two-phase session state: per-phase page budgets (see
    /// `ReconcilePending`'s doc comment, audit final pre-mainnet W9, and
    /// `private_channel_sync::MAX_META_PAGES_PER_SESSION`), strictly
    /// advancing cursors, and the session-cumulative `Accepted` count that
    /// completion requires (round 4). Since l2-node 0.149.0 it may be
    /// seeded from the persisted resume row, so `accepted_total` is then
    /// the WALK's cumulative count (all its sessions).
    session: private_channel_sync::SyncSession,
    /// `session.accepted_total` when this session started (the part
    /// carried over from earlier sessions of the walk), so the attempt
    /// throttle can tell whether THIS session admitted anything new.
    accepted_base: usize,
    /// Resume-row context for the per-page row write (`None` = the resume
    /// cursor is off, `[private_channel_sync] resume_ttl_hours = 0`).
    resume: Option<private_channel_sync::ResumeSeed>,
    /// This session is a same-peer continuation of a stored walk (ONE
    /// request to the peer that issued its cursors). An auth rejection by
    /// that peer abandons the walk; a session that makes no cursor progress
    /// counts as a stall (`note_private_channel_sync_stall`), and
    /// `MAX_RESUME_STALLS` consecutive stalls abandon it too.
    same_peer_resume: bool,
}

/// Per-pending-outbound-news-sync state (P-3). Audit final pre-mainnet W9:
/// previously a bare `PeerId` (news-sync has no per-subject key, it's a
/// single global feed) — now a small struct so the requester-side paging
/// budget (see `ReconcilePending`'s doc comment) has somewhere to live.
#[derive(Debug, Clone)]
struct NewsSyncPending {
    peer_id: PeerId,
    pages_fetched: u32,
    consecutive_unproductive_pages: u32,
}

/// Command from the API/router task → network task asking it to lazily pull a
/// wallet's identity bundle (P-1). Sent over `identity_sync_tx`; handled in the
/// `run` select loop by `maybe_trigger_identity_sync`.
#[derive(Debug, Clone)]
pub struct IdentitySyncCommand {
    pub wallet: String,
    pub scopes: u8,
}

/// Command from the API/WS layer → network task: a wallet authenticated
/// here, optionally with a wallet-signed dm-sync backfill authorization for
/// THIS node (audit W5). Sent over `dm_subscribe_tx` on every REST
/// authenticated call and every WS connect.
#[derive(Debug, Clone)]
pub struct DmSubscribeEvent {
    pub wallet: String,
    pub wallet_claim: Option<dm_sync::WalletAuthClaim>,
}

/// Command from the API layer → network task: a wallet federated a private
/// channel to this node (`federate_channel`, `api/routes.rs`), optionally
/// with a wallet-signed private-channel-sync backfill authorization for
/// THIS node. Sent over `private_channel_sync_tx`. Closes the F2 backfill
/// gap (l2-node 0.138.0+) — see `network::private_channel_sync`'s module
/// doc for the full design.
///
/// l2-node 0.142.0: also sent by the REST auth middleware and the WS auth
/// frame when a request carries a valid pchansync claim (`channel_id:
/// None`, at most once per wallet per 60 s — `api::auth`): the network task
/// then caches the claim and re-evaluates every private channel the wallet
/// federated here, through the normal attempt throttle (no bypass).
/// l2-node 0.150.0 (Phase E): "every private channel" is the union of the
/// wallet's `LOCAL_CHANNEL_FED` rows and its `LOCAL_CHANNEL_HOMES` rows
/// (through the `LOCAL_CHANNEL_HOMES_BY_WALLET` index), at most
/// `MAX_CLAIM_REFRESH_CHANNELS` from each source.
#[derive(Debug, Clone)]
pub struct PrivateChannelSyncTrigger {
    /// `Some` = one channel (federate call — a fresh claim may bypass the
    /// attempt throttle down to its 60 s floor — or a cancelled cleanup).
    /// `None` = every private channel in `LOCAL_CHANNEL_FED` ∪
    /// `LOCAL_CHANNEL_HOMES` for `wallet`, never bypassing.
    pub channel_id: Option<u64>,
    /// The wallet whose membership/backfill this concerns.
    pub wallet: String,
    /// The verified claim, if any (wallet-direct or device-signed).
    pub wallet_claim: Option<private_channel_sync::WalletAuthClaim>,
}

/// Max private channels re-evaluated for one wallet per claim refresh
/// (`PrivateChannelSyncTrigger { channel_id: None, .. }`), PER SOURCE
/// (`LOCAL_CHANNEL_FED` and the HOMES wallet index, l2-node 0.150.0 — so
/// at most twice this many distinct channels per refresh).
pub const MAX_CLAIM_REFRESH_CHANNELS: usize = 256;

/// Lazily built snapshot of the gossip topics some connected peer
/// subscribes (`NetworkService::remote_subscribed_topics`), shared across
/// the channels one claim refresh / sweep tick evaluates (l2-node 0.150.0).
type RemoteSubscriberCache = Option<HashSet<libp2p::gossipsub::TopicHash>>;

/// Max wallets with a cached private-channel-sync claim (oldest/expired
/// evicted first when full).
pub const MAX_CACHED_PCHANSYNC_CLAIMS: usize = 100_000;

/// Cross-channel smuggling defense (Security Audit W1, 0.47.0).
/// Returns `true` iff the envelope's payload claims the same
/// `channel_id` we are reconciling. Envelopes that target a
/// different channel are dropped before routing — a malicious
/// responder cannot use our reconcile request to seed arbitrary
/// channel content into our local indexes.
///
/// We do not need to be fully strict here: the worst that happens
/// on a false-positive (we accept an envelope whose payload doesn't
/// even have a `channel_id` field) is that the envelope goes through
/// the standard router and is rejected by payload-specific
/// validation. This decodes the FULL typed payload via
/// `deserialize_payload` — not a narrower probe struct, which is what
/// caused two earlier rounds of this exact bug (a probe with fewer
/// fields than the real payload fails outright against the
/// positional msgpack-array wire form `sdk-rust` uses) — so despite
/// the "pre-check" framing, this keeps the obvious smuggle out of the
/// router pipeline using the same decode logic the router itself uses.
/// Pure completeness-gate check for `NetworkService::maybe_trigger_backfill`
/// (l2-node 0.136.0 fix). `None` (never reached natural completion) is
/// always due, regardless of `catchup_interval_hours` — that knob only
/// governs re-checking an ALREADY-completed channel. `catchup_interval_hours
/// == 0` disables re-checking completed channels (but never makes a
/// never-completed channel not-due).
fn channel_backfill_due(completed_at: Option<u64>, now: u64, catchup_interval_hours: u64) -> bool {
    match completed_at {
        None => true,
        Some(completed) => {
            catchup_interval_hours > 0
                && now.saturating_sub(completed) >= catchup_interval_hours.saturating_mul(3600)
        }
    }
}

/// Ranks a resolved comparison's candidates by how much content they
/// reported, descending (l2-node 0.137.0) — the order
/// `finalize_reconcile_comparison` tries them in. Ties keep original
/// (first-seen) order, since `sort_by_key` is stable.
fn rank_reconcile_candidates_by_size(
    candidates: &[(PeerId, reconcile::ReconcileResponse)],
) -> Vec<usize> {
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(candidates[i].1.envelopes.len()));
    order
}

/// Splits a comparison's VERIFIED trial outcomes (l2-node 0.137.0) into
/// who should be treated as competitive vs. meaningfully behind, for
/// `record_reconcile_peer_result`. `trials` is `(peer, had_real_progress)`
/// in the order they were actually tried — see `finalize_reconcile_
/// comparison`'s doc comment for why this must be fed VERIFIED outcomes
/// (never raw, pre-verification reported counts) and why a candidate
/// never tried at all (because an earlier one already won) appears in
/// neither list.
fn split_reconcile_trial_results(trials: &[(PeerId, bool)]) -> (Vec<PeerId>, Vec<PeerId>) {
    let mut competitive = Vec::new();
    let mut behind = Vec::new();
    for &(peer, had_progress) in trials {
        if had_progress {
            competitive.push(peer);
        } else {
            behind.push(peer);
        }
    }
    (competitive, behind)
}

/// `true` once `consecutive_losses` has reached `threshold` (l2-node
/// 0.137.0) — `[backfill] stale_peer_threshold`, `0` meaning "disabled,
/// never flag anyone stale" (mirrors `channel_catchup_interval_hours`'s
/// `0`-disables convention elsewhere in this same feature).
fn is_peer_stale(consecutive_losses: u32, threshold: u32) -> bool {
    threshold > 0 && consecutive_losses >= threshold
}

/// `true` iff `env_bytes` (an envelope the router just answered
/// `Duplicate` for) is BYTE-IDENTICAL to the copy stored locally under its
/// `msg_id` (l2-node 0.141.0). The router's duplicate check runs before
/// msg_id binding and signature verification and is keyed by msg_id alone,
/// so `Duplicate` by itself proves nothing (recurring bug shape #19); but
/// the stored bytes were fully verified at ingest, so byte identity is as
/// strong as re-verifying the signature — a forged envelope reusing a known
/// msg_id with a different payload/signature fails here. Only the top-level
/// `Envelope` is decoded (for `msg_id`), never the payload. Used ONLY as
/// in-sync evidence for the requester's attempt throttle, never for
/// completion. Fails safe: stored bytes that were re-encoded at ingest
/// (snapshot import, a router re-encode) simply do not count.
pub(crate) fn duplicate_is_verified(storage: &Storage, env_bytes: &[u8]) -> bool {
    let Ok(env) = rmp_serde::from_slice::<Envelope>(env_bytes) else {
        return false;
    };
    matches!(storage.get_message(&env.msg_id), Ok(Some(stored)) if stored == env_bytes)
}

/// Generic sync-protocol responder budget per `(peer, channel)` (l2-node
/// 0.141.0). `sync` shares `reconcile::ResponderLimits` with reconcile, so
/// its former LIFETIME cap (`sync::TOTAL_ENVELOPES_CAP`, 5,000 per process)
/// became a rolling window too: the same 5,000 burst, refilled at this rate.
const SYNC_RESPONDER_REFILL_PER_HOUR: u64 = 5_000;

fn envelope_targets_channel(env_bytes: &[u8], expected_channel: u64) -> bool {
    use crate::messages::envelope::Envelope;
    use crate::messages::types::{deserialize_payload, DeserializedPayload, MessageType};
    let envelope: Envelope = match rmp_serde::from_slice(env_bytes) {
        Ok(e) => e,
        Err(_) => return false,
    };
    // Code-audit finding (2026-10-01, round 3): both prior fixes here
    // deserialized into a hand-rolled, FEWER-FIELDS-THAN-the-real-struct
    // probe (`ChannelIdOnlyPayload { channel_id: u64 }`, then
    // `ChannelIdOptionalPayload { target_id, channel_id }`) to read just
    // the field this check needs. That sidesteps the original
    // `serde_json::Value`-vs-binary-field crash, but reintroduces a
    // narrower version of the SAME class of bug: `rmp_serde` decodes a
    // msgpack ARRAY (the wire form `sdk-rust` uses, per
    // `validation.rs`'s documented dual-decode requirement) by matching
    // the array's element COUNT against the target struct's field
    // count — a probe struct with fewer fields than the real payload
    // (every multi-field type here) fails with `LengthMismatch`, not a
    // partial positional read of the first N elements. Confirmed
    // empirically against real `ChatMessagePayload`/`EditPayload` wire
    // bytes. Net effect: array-encoded envelopes for every type in the
    // first arm below (all of which have 2+ fields, i.e. all but
    // `ChannelJoin`/`ChannelLeave`/`ChannelDelete`) were STILL silently
    // dropped during reconcile backfill — the exact bug this session
    // set out to fix, just not fully closed by the first attempt.
    //
    // Fix: decode through `deserialize_payload`, the one function in
    // this codebase that already decodes every payload type via its
    // REAL, complete struct — which by construction has exactly the
    // right field count for both the map and array wire forms, so
    // `rmp_serde` dispatches to the correct `visit_map`/`visit_seq` path
    // transparently. This is also the canonical decode path every other
    // ingestion route (gossip, `POST /api/v1/messages`, identity-sync)
    // already funnels through, so this is a full typed decode, not a
    // narrower probe — the exact shortcut that caused rounds 1 and 2.
    match envelope.msg_type {
        MessageType::ChatMessage
        | MessageType::ChannelPinMessage
        | MessageType::ChannelUnpinMessage
        | MessageType::ChannelJoin
        | MessageType::ChannelLeave
        // P-3b: channel-metadata envelopes ride the first reconcile page, so
        // bind them to the reconciled channel too (a relay can't smuggle a
        // ChannelCreate/Update for a different channel).
        | MessageType::ChannelCreate
        | MessageType::ChannelUpdate
        // ChannelDelete also rides the metadata-reconcile page; bind it to the
        // reconciled channel so a relay can't smuggle a delete for another channel.
        | MessageType::ChannelDelete
        // Code-audit finding (2026-10-01, round 3): Kick/Ban/Unban are
        // indexed into CHANNEL_META_MSGS by `update_indexes` (router.rs)
        // exactly like Create/Update/Delete above, and `channel_meta_envelopes`
        // serves them on the same reconcile page — so they need the same
        // binding, for the same reason. Previously fell through to the
        // unconditional `_ => true` below, which isn't a forgery risk (the
        // router re-authorizes moderator permission from the payload's own
        // channel_id regardless of which reconcile page it arrived on), but
        // did defeat this function's whole per-channel-scoping purpose for
        // these three types.
        | MessageType::ChannelKick
        | MessageType::ChannelBan
        | MessageType::ChannelUnban
        // Moderator propagation (l2-node 0.140.0): indexed into
        // CHANNEL_META_MSGS and served on the same page, so bound the same way.
        | MessageType::ChannelAddModerator
        | MessageType::ChannelRemoveModerator
        // Mutes (l2-node 0.152.0, G6): indexed into CHANNEL_META_MSGS and
        // served on the metadata pages like the pins above.
        | MessageType::ChannelMute
        | MessageType::ChannelUnmute => {
            match deserialize_payload(envelope.msg_type, &envelope.payload) {
                Ok(DeserializedPayload::ChatMessage(p)) => p.channel_id == expected_channel,
                Ok(DeserializedPayload::ChannelPinMessage(p)) => p.channel_id == expected_channel,
                Ok(DeserializedPayload::ChannelUnpinMessage(p)) => p.channel_id == expected_channel,
                Ok(DeserializedPayload::ChannelJoin(p)) => p.channel_id == expected_channel,
                Ok(DeserializedPayload::ChannelLeave(p)) => p.channel_id == expected_channel,
                Ok(DeserializedPayload::ChannelCreate(p)) => p.channel_id == expected_channel,
                Ok(DeserializedPayload::ChannelUpdate(p)) => p.channel_id == expected_channel,
                Ok(DeserializedPayload::ChannelDelete(p)) => p.channel_id == expected_channel,
                Ok(DeserializedPayload::ChannelKick(p)) => p.channel_id == expected_channel,
                Ok(DeserializedPayload::ChannelBan(p)) => p.channel_id == expected_channel,
                Ok(DeserializedPayload::ChannelUnban(p)) => p.channel_id == expected_channel,
                Ok(DeserializedPayload::ChannelAddModerator(p)) => p.channel_id == expected_channel,
                Ok(DeserializedPayload::ChannelRemoveModerator(p)) => {
                    p.channel_id == expected_channel
                }
                Ok(DeserializedPayload::ChannelMute(p)) => p.channel_id == expected_channel,
                Ok(DeserializedPayload::ChannelUnmute(p)) => p.channel_id == expected_channel,
                // A decode failure is conservatively rejected. An `Ok` of
                // some OTHER variant should be unreachable (it would mean
                // this match arm's type list and the inner one have drifted
                // out of sync) — logged rather than silently swallowed, so
                // that drift surfaces instead of quietly becoming a drop.
                Ok(other) => {
                    tracing::debug!(
                        msg_type = ?envelope.msg_type,
                        variant = ?other,
                        "envelope_targets_channel: decoded to an unexpected \
                         DeserializedPayload variant for this msg_type — \
                         type-list desync, rejecting conservatively"
                    );
                    false
                }
                Err(_) => false,
            }
        }
        // Security-audit finding (2026-10-01, round 3): `ChatEdit`/
        // `ChatDelete`/`ChatReaction` (`EditPayload`/`DeletePayload`/
        // `ReactionPayload`) carry `channel_id: Option<u64>` — and it is
        // AUTHOR-CONTROLLED, unvalidated by the router (`authorize_edit_
        // delete` never reads it). `router.rs`'s `resolve_chat_channel_id`
        // deliberately ignores this field entirely and re-derives the real
        // channel by looking up the ORIGINAL message via `target_id` — it
        // treats an absent `channel_id` and a WRONG one identically (both
        // irrelevant), never trusting either. An earlier version of this
        // arm rejected on `Some(mismatched)`, which doesn't just fail to
        // add protection — it actively drops genuine edits/deletes whose
        // author set a foreign/bogus `channel_id` on their OWN message
        // (something the router happily applies, since it never looks at
        // this field). That reopens the W6 "deleted-for-everyone content
        // resurfaces on a backfilling node" class one layer up: a
        // perfectly valid delete marker never reaches cold-joining nodes
        // because this pre-check dropped it first. Since the router is
        // airtight regardless of what this field says, deferring
        // unconditionally costs nothing and removes a real harm.
        MessageType::ChatEdit | MessageType::ChatDelete | MessageType::ChatReaction => true,
        // l2-node 0.143.0 (round-2 audit W-C): channel key envelopes are never
        // served by reconcile (they are not in CHANNEL_MSGS), so one arriving
        // here is a responder injecting it. Sync ingestion skips the drift
        // check and rate limits, which would let a back-dated `key_ts` reach
        // a victim node's arbitration. Refuse it outright. (The other sync
        // protocols allow-list their own types and never carry key envelopes;
        // as defence in depth the router's Step 7h accepts sync-path key
        // envelopes only when they wrap the already recorded winner.)
        MessageType::ChannelKeyEnvelope => false,
        // Non-channel message types should not appear in
        // CHANNEL_MSGS, but be conservative — accept them and let
        // the router decide.
        _ => true,
    }
}

/// Test hook for `envelope_targets_channel` (used by the key-arbitration
/// tests in `api::epoch_arbitration_tests`).
#[cfg(test)]
pub(crate) fn envelope_targets_channel_for_tests(env_bytes: &[u8], expected_channel: u64) -> bool {
    envelope_targets_channel(env_bytes, expected_channel)
}

#[cfg(test)]
mod envelope_targets_channel_tests {
    //! Found live, 2026-10-01: `envelope_targets_channel` used to
    //! deserialize into `serde_json::Value` to read `channel_id`
    //! generically — which hard-errors on ANY MessagePack binary field,
    //! and every ENCRYPTED `ChatMessage` (the default for every Public/
    //! ReadPublic/Private channel in this project) has one
    //! (`enc_content`/`enc_nonce`). This silently dropped essentially
    //! all real chat content during reconcile/cold-join backfill
    //! project-wide — confirmed against real wire bytes from a live
    //! node before fixing. These tests pin the fix: a targeted struct
    //! deserialization that never touches the binary fields at all.
    use super::*;
    use crate::messages::envelope::Envelope;
    use crate::messages::types::{ChatMessagePayload, ContentRating, MessageType};

    fn encrypted_chat_envelope(channel_id: u64) -> Vec<u8> {
        let payload = ChatMessagePayload {
            channel_id,
            content: String::new(),
            content_rating: ContentRating::default(),
            reply_to: None,
            mentions: vec![],
            attachments: vec![],
            // The exact shape that broke the old `serde_json::Value`
            // path: real binary data, not empty/None.
            enc_content: Some(vec![1, 2, 3, 4, 5]),
            enc_nonce: Some([7u8; 24]),
            key_epoch: Some(1),
            buttons: vec![],
            via_button: false,
        };
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChatMessage,
            msg_id: [9u8; 32],
            author: "klv1author".to_string(),
            timestamp: 1_700_000_000_000,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![0u8; 64],
            relay_path: vec![],
        };
        rmp_serde::to_vec_named(&envelope).unwrap()
    }

    #[test]
    fn encrypted_chat_message_correctly_matches_its_own_channel() {
        let env_bytes = encrypted_chat_envelope(42);
        assert!(
            envelope_targets_channel(&env_bytes, 42),
            "an encrypted ChatMessage must still be recognized as targeting \
             its own channel_id — this is exactly the case that used to \
             hard-fail on the enc_content/enc_nonce binary fields"
        );
    }

    #[test]
    fn encrypted_chat_message_correctly_rejects_a_different_channel() {
        let env_bytes = encrypted_chat_envelope(42);
        assert!(
            !envelope_targets_channel(&env_bytes, 99),
            "cross-channel smuggling defense must still work for encrypted \
             messages, not just plaintext ones"
        );
    }

    /// Sanity check that the fix didn't regress the plaintext (non-
    /// encrypted) case, which never hit this bug.
    #[test]
    fn plaintext_chat_message_still_matches_its_own_channel() {
        let payload = ChatMessagePayload {
            channel_id: 7,
            content: "hello".to_string(),
            content_rating: ContentRating::default(),
            reply_to: None,
            mentions: vec![],
            attachments: vec![],
            enc_content: None,
            enc_nonce: None,
            key_epoch: None,
            buttons: vec![],
            via_button: false,
        };
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChatMessage,
            msg_id: [1u8; 32],
            author: "klv1author".to_string(),
            timestamp: 1_700_000_000_000,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![0u8; 64],
            relay_path: vec![],
        };
        let env_bytes = rmp_serde::to_vec_named(&envelope).unwrap();
        assert!(envelope_targets_channel(&env_bytes, 7));
        assert!(!envelope_targets_channel(&env_bytes, 8));
    }

    /// A malformed/undecodable envelope must still be conservatively
    /// rejected, not panic or default to "matches everything".
    #[test]
    fn garbage_bytes_do_not_match_any_channel() {
        assert!(!envelope_targets_channel(b"not a valid envelope", 42));
    }

    /// Round-3 code-audit finding: the first fix replaced
    /// `serde_json::Value` with a narrower, FEWER-FIELDS-THAN-the-real-
    /// struct probe (`ChannelIdOnlyPayload { channel_id: u64 }`), which
    /// sidestepped the binary-field crash but reintroduced the same class
    /// of bug for `sdk-rust`'s positional msgpack-ARRAY wire form:
    /// `rmp_serde` matches the array's element count against the target
    /// struct's field count, so a 1-field probe against `ChatMessagePayload`'s
    /// real 11-element array fails `LengthMismatch` rather than reading the
    /// first element — meaning array-encoded chat messages were STILL
    /// silently dropped during backfill. This pins the fix: decoding
    /// through `deserialize_payload` (the real, complete struct) handles
    /// both wire forms.
    #[test]
    fn array_encoded_encrypted_chat_message_matches_its_own_channel() {
        let payload = ChatMessagePayload {
            channel_id: 42,
            content: String::new(),
            content_rating: ContentRating::default(),
            reply_to: None,
            mentions: vec![],
            attachments: vec![],
            enc_content: Some(vec![1, 2, 3, 4, 5]),
            enc_nonce: Some([7u8; 24]),
            key_epoch: Some(1),
            buttons: vec![],
            via_button: false,
        };
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChatMessage,
            msg_id: [8u8; 32],
            author: "klv1author".to_string(),
            timestamp: 1_700_000_000_000,
            lamport_ts: 0,
            // Positional array encoding, matching sdk-rust's wire form —
            // NOT `to_vec_named`.
            payload: rmp_serde::to_vec(&payload).unwrap(),
            signature: vec![0u8; 64],
            relay_path: vec![],
        };
        let env_bytes = rmp_serde::to_vec_named(&envelope).unwrap();
        assert!(
            envelope_targets_channel(&env_bytes, 42),
            "an sdk-rust (array-encoded) encrypted ChatMessage must still be \
             recognized as targeting its own channel_id"
        );
        assert!(!envelope_targets_channel(&env_bytes, 99));
    }

    /// `ChannelCreatePayload` (10 fields, since the `id_derivation_ts`
    /// security fix) is a second, independently-shaped array-wire-form
    /// regression case: a 1-field probe against a 10-element array also
    /// fails `LengthMismatch`, distinct from the 11-field
    /// `ChatMessagePayload` case above.
    #[test]
    fn array_encoded_channel_create_matches_its_own_channel() {
        use crate::messages::types::{ChannelCreatePayload, ChannelType, ModerationPolicy};
        let payload = ChannelCreatePayload {
            channel_id: 42,
            slug: "general".to_string(),
            channel_type: ChannelType::Public,
            display_name: None,
            description: None,
            content_rating: ContentRating::default(),
            moderation: ModerationPolicy {
                admins: vec![],
                rules: None,
            },
            encryption_enabled: None,
            history_visibility: None,
            id_derivation_ts: None,
        };
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChannelCreate,
            msg_id: [6u8; 32],
            author: "klv1author".to_string(),
            timestamp: 1_700_000_000_000,
            lamport_ts: 0,
            payload: rmp_serde::to_vec(&payload).unwrap(),
            signature: vec![0u8; 64],
            relay_path: vec![],
        };
        let env_bytes = rmp_serde::to_vec_named(&envelope).unwrap();
        assert!(envelope_targets_channel(&env_bytes, 42));
        assert!(!envelope_targets_channel(&env_bytes, 99));
    }

    /// Round-3 code-audit finding: `ChannelKick`/`ChannelBan`/`ChannelUnban`
    /// ride the same metadata-reconcile page as Create/Update/Delete, so
    /// they need the same per-channel binding — they previously fell
    /// through to the unconditional `_ => true` catch-all, defeating this
    /// function's scoping purpose for these three types.
    #[test]
    fn channel_kick_ban_unban_are_bound_to_their_own_channel() {
        use crate::messages::types::{ChannelBanPayload, ChannelKickPayload, ChannelUnbanPayload};

        let kick = chat_envelope(
            MessageType::ChannelKick,
            rmp_serde::to_vec_named(&ChannelKickPayload {
                channel_id: 42,
                target_user: "klv1target".to_string(),
                reason: None,
            })
            .unwrap(),
        );
        assert!(envelope_targets_channel(&kick, 42));
        assert!(!envelope_targets_channel(&kick, 99));

        let ban = chat_envelope(
            MessageType::ChannelBan,
            rmp_serde::to_vec_named(&ChannelBanPayload {
                channel_id: 42,
                target_user: "klv1target".to_string(),
                reason: None,
                duration_secs: 0,
            })
            .unwrap(),
        );
        assert!(envelope_targets_channel(&ban, 42));
        assert!(!envelope_targets_channel(&ban, 99));

        let unban = chat_envelope(
            MessageType::ChannelUnban,
            rmp_serde::to_vec_named(&ChannelUnbanPayload {
                channel_id: 42,
                target_user: "klv1target".to_string(),
            })
            .unwrap(),
        );
        assert!(envelope_targets_channel(&unban, 42));
        assert!(!envelope_targets_channel(&unban, 99));
    }

    // --- ChatEdit/ChatDelete/ChatReaction (round-3 security-audit finding) ---
    // `channel_id: Option<u64>` on these three types is author-controlled
    // and the router (`resolve_chat_channel_id`) never trusts it — it
    // re-derives the real channel via `target_id` and treats an absent
    // `channel_id` and a WRONG one identically (both irrelevant). Rejecting
    // on `Some(mismatched)` doesn't add protection; it drops genuine edits/
    // deletes whose author set a foreign channel_id on their OWN message,
    // reopening the W6 "deleted content resurfaces on a backfilling node"
    // class one layer up. So this arm defers unconditionally — these tests
    // pin that, across all three types and both a present and absent
    // channel_id, rather than re-deriving behavior from the (now much
    // simpler) implementation.
    use crate::messages::types::{DeletePayload, EditPayload, ReactionPayload};

    fn chat_envelope(msg_type: MessageType, payload_bytes: Vec<u8>) -> Vec<u8> {
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type,
            msg_id: [3u8; 32],
            author: "klv1author".to_string(),
            timestamp: 1_700_000_000_000,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: vec![0u8; 64],
            relay_path: vec![],
        };
        rmp_serde::to_vec_named(&envelope).unwrap()
    }

    #[test]
    fn chat_delete_defers_to_router_regardless_of_its_own_channel_id() {
        let env_bytes = chat_envelope(
            MessageType::ChatDelete,
            rmp_serde::to_vec_named(&DeletePayload {
                target_id: [5u8; 32],
                channel_id: Some(42),
            })
            .unwrap(),
        );
        assert!(envelope_targets_channel(&env_bytes, 42));
        assert!(
            envelope_targets_channel(&env_bytes, 99),
            "a foreign channel_id on a delete the router never trusts must \
             not cause this pre-check to drop a genuine delete"
        );

        let absent = chat_envelope(
            MessageType::ChatDelete,
            rmp_serde::to_vec_named(&DeletePayload {
                target_id: [5u8; 32],
                channel_id: None,
            })
            .unwrap(),
        );
        assert!(envelope_targets_channel(&absent, 42));
    }

    #[test]
    fn chat_edit_defers_to_router_regardless_of_its_own_channel_id() {
        let payload = EditPayload {
            target_id: [5u8; 32],
            channel_id: Some(42),
            content: "edited".to_string(),
            edited_at: 1_700_000_000_000,
            title: None,
            tags: None,
            attachments: None,
            buttons: None,
            enc_content: Some(vec![1, 2, 3]),
            enc_nonce: Some([9u8; 24]),
            key_epoch: Some(1),
        };
        let env_bytes = chat_envelope(MessageType::ChatEdit, rmp_serde::to_vec_named(&payload).unwrap());
        assert!(envelope_targets_channel(&env_bytes, 99));

        // Also pin the array wire form explicitly.
        let env_bytes_array =
            chat_envelope(MessageType::ChatEdit, rmp_serde::to_vec(&payload).unwrap());
        assert!(envelope_targets_channel(&env_bytes_array, 99));
    }

    #[test]
    fn chat_reaction_defers_to_router_regardless_of_its_own_channel_id() {
        let payload = ReactionPayload {
            target_id: [5u8; 32],
            channel_id: Some(42),
            emoji: "👍".to_string(),
            remove: false,
        };
        let env_bytes =
            chat_envelope(MessageType::ChatReaction, rmp_serde::to_vec_named(&payload).unwrap());
        assert!(envelope_targets_channel(&env_bytes, 99));
    }
}

/// Smuggling defense for identity-sync responses (P-1). Returns `true` iff the
/// envelope is an identity message type the requester asked for (`scopes`).
///
/// This bounds an identity-sync response to identity types — a responder can't
/// inject an unrelated type (e.g. a chat message or channel-create) through the
/// identity-sync path. It does NOT bind to a specific wallet on purpose: a
/// device-resolve-miss pull is keyed by the device address, but the resolved
/// bundle's `DeviceDelegation` is authored by the WALLET, so a wallet-author
/// check would wrongly drop it. That's safe — `process_synced_message`
/// signature-validates every envelope, so an envelope for a different wallet is
/// either genuine (harmlessly backfills that wallet's real data) or rejected.
fn envelope_targets_scope(env_bytes: &[u8], scopes: u8) -> bool {
    use crate::messages::envelope::Envelope;
    let envelope: Envelope = match rmp_serde::from_slice(env_bytes) {
        Ok(e) => e,
        Err(_) => return false,
    };
    identity_sync::type_in_scopes(envelope.msg_type_u8(), scopes)
}

/// Which backfill a `DeletionRequest` arrived through (l2-node 0.151.0,
/// G5) — the scope its target must belong to (`deletion_request_fit`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeletionScope {
    /// Channel reconcile / private-channel sync for this channel.
    Channel(u64),
    /// News-sync.
    News,
    /// DM-sync.
    Dm,
}

/// Outcome of `deletion_request_fit` (l2-node 0.151.0, audit W-B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeletionFit {
    /// Not a `DeletionRequest`, or one bound to this sync: route it.
    Fits,
    /// A well-formed `DeletionRequest` this sync does not take (wrong scope,
    /// outside the window, `AllUserContent`): skip it — neither progress nor
    /// a peer fault (windows and versions differ between honest nodes).
    Neutral,
    /// Undecodable envelope or `DeletionRequest` payload: a fault (taint).
    Malformed,
}

/// Receiver-side binding of a synced `DeletionRequest` (0x50) to the
/// backfill it arrived through (l2-node 0.151.0, G5). `true` for every
/// other type (the per-protocol checks handle those). A `DeletionRequest`
/// must be `SingleMessage` with a target; when the target is stored here it
/// must be a chat message of the synced channel / news content / a DM,
/// matching `Storage::index_deletion_request` on the responder, so a relay
/// cannot replay an unrelated request through a protocol that would never
/// serve it. An UNKNOWN target is accepted: responders withhold erased
/// originals (D4), so a fresh node gets the request without its target —
/// the router then records it only as a pending row that hides nothing
/// unless a message by the same author with that id is stored later.
fn deletion_request_fit(storage: &Storage, env_bytes: &[u8], scope: DeletionScope, min_ts_ms: u64) -> DeletionFit {
    use crate::messages::types::{DeletionRequestPayload, DeletionType, MessageType};
    use crate::storage::rocks::DeletionTargetKind;
    let Ok(env) = rmp_serde::from_slice::<Envelope>(env_bytes) else {
        return DeletionFit::Malformed;
    };
    if env.msg_type != MessageType::DeletionRequest {
        return DeletionFit::Fits;
    }
    let target = match rmp_serde::from_slice::<DeletionRequestPayload>(&env.payload) {
        Ok(DeletionRequestPayload { delete_type: DeletionType::SingleMessage, target_id: Some(t) }) => t,
        // `AllUserContent` is never indexed into any backfill side-index;
        // a well-formed one is simply not this protocol's (neutral).
        Ok(_) => return DeletionFit::Neutral,
        // An undecodable payload is a broken envelope (audit W-B: taint).
        Err(_) => return DeletionFit::Malformed,
    };
    let fits = match (storage.deletion_target_kind(&target), scope) {
        // Unknown target → pending row: only inside this sync's window
        // (audit W1 — the responder serves the request within the same
        // window; anything older can never meet its target here).
        (None, _) => env.timestamp >= min_ts_ms,
        (Some(DeletionTargetKind::Chat(cid)), DeletionScope::Channel(want)) => cid == want,
        (Some(DeletionTargetKind::News), DeletionScope::News) => true,
        (Some(DeletionTargetKind::Dm(_)), DeletionScope::Dm) => true,
        _ => false,
    };
    if fits {
        DeletionFit::Fits
    } else {
        DeletionFit::Neutral
    }
}

/// `true` iff `env_bytes` is a `DeletionRequest` (top-level decode only).
fn is_deletion_request(env_bytes: &[u8]) -> bool {
    rmp_serde::from_slice::<Envelope>(env_bytes)
        .is_ok_and(|e| e.msg_type == crate::messages::types::MessageType::DeletionRequest)
}

/// `true` iff `env_bytes` is a `SingleMessage` `DeletionRequest` whose target
/// is NOT stored here — after routing, i.e. it was accepted only as a pending
/// row (l2-node 0.151.0, audit W1). Such an acceptance proves nothing about
/// the responder's history and must not count as progress or completion.
fn pending_only_deletion(storage: &Storage, env_bytes: &[u8]) -> bool {
    use crate::messages::types::{DeletionRequestPayload, MessageType};
    let Ok(env) = rmp_serde::from_slice::<Envelope>(env_bytes) else { return false };
    if env.msg_type != MessageType::DeletionRequest {
        return false;
    }
    match rmp_serde::from_slice::<DeletionRequestPayload>(&env.payload) {
        Ok(DeletionRequestPayload { target_id: Some(t), .. }) => !storage.message_exists(&t).unwrap_or(false),
        _ => false,
    }
}

/// Window in seconds for a `days` setting where `u64::MAX` means unlimited
/// (`[backfill] max_age_days`).
fn days_window_secs_max_unlimited(days: u64) -> u64 {
    if days == u64::MAX { u64::MAX } else { days.saturating_mul(24 * 3600) }
}

/// Window in seconds for a `days` setting where `0` means unlimited
/// (`news_max_age_days`, `[dm] backfill_max_age_days`,
/// `[private_channel_sync] max_age_days`).
fn days_window_secs_zero_unlimited(days: u64) -> u64 {
    if days == 0 { u64::MAX } else { days.saturating_mul(24 * 3600) }
}

/// Earliest envelope timestamp (ms) inside a backfill window of
/// `max_age_secs` (`u64::MAX` = unlimited → 0).
fn window_start_ms(max_age_secs: u64) -> u64 {
    if max_age_secs == u64::MAX {
        0
    } else {
        now_ms().saturating_sub(max_age_secs.saturating_mul(1000))
    }
}

/// Max distinct authors one backfill page feeds into the identity-pull gate
/// (G9, l2-node 0.151.0). The gate's own per-interval budget bounds the
/// pulls; this bounds the per-page bookkeeping and `USERS` reads.
const MAX_BACKFILLED_AUTHORS_PER_PAGE: usize = 32;

/// Record the author of an `Accepted` backfilled envelope for the
/// identity-pull gate (G9): only types `identity_sync::
/// triggers_identity_check` allows, deduplicated, at most
/// `MAX_BACKFILLED_AUTHORS_PER_PAGE` per page.
fn note_backfilled_author(out: &mut Vec<(String, u8)>, author: String, msg_type: u8) {
    if out.len() >= MAX_BACKFILLED_AUTHORS_PER_PAGE
        || !identity_sync::triggers_identity_check(msg_type)
        || out.iter().any(|(a, _)| *a == author)
    {
        return;
    }
    out.push((author, msg_type));
}

/// Smuggling defense for news-sync responses (P-3): accept only news-feed
/// message types, so a responder can't inject a non-news type through this
/// path. Every envelope is still signature-validated by `process_synced_message`.
fn envelope_targets_news(env_bytes: &[u8]) -> bool {
    use crate::messages::envelope::Envelope;
    let envelope: Envelope = match rmp_serde::from_slice(env_bytes) {
        Ok(e) => e,
        Err(_) => return false,
    };
    news_sync::is_news_type(envelope.msg_type_u8())
}

/// Current wall-clock time in Unix milliseconds (0 if the clock is before the
/// epoch, which never happens in practice).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Upper bound on `NetworkService::dm_sync_cancelled_siblings` (l2-node
/// 0.153.0). Each dm-sync trigger cancels at most `FANOUT - 1` siblings and
/// every entry is removed when its response or failure arrives; the bound
/// only matters if responses never come. When full, new siblings are simply
/// not remembered (their responses are ignored, as before 0.153.0).
const MAX_DM_SYNC_CANCELLED_SIBLINGS: usize = 10_000;

/// What applying one dm-sync page did (l2-node 0.153.0).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DmSyncTally {
    /// `Accepted` (or `Duplicate`) by the router — the session's progress.
    pub admitted: usize,
    /// Refused before routing as foreign / undecodable (taint), or a
    /// malformed deletion request.
    pub dropped: usize,
    /// Skipped or refused for a reason an honest responder can cause
    /// (`dm_sync::DmSyncFit::Neutral`, a neutral router refusal of a
    /// revision-1 type, a neutral deletion request): neither progress nor a
    /// fault.
    pub neutral: usize,
}

/// Validate and apply one dm-sync page for `wallet` (Phase 2; factored out
/// of `handle_dm_sync_event` in l2-node 0.153.0). Every envelope is bound to
/// the wallet's scope first (`dm_sync::dm_envelope_fit` — the type
/// allow-list `dm_sync::is_dm_type` plus, for the revision-1 types, the
/// wallet binding), deletion requests to a DM target
/// (`deletion_request_fit`), and is then re-validated by the router's SYNC
/// pipeline (`process_synced_message`), so a relaying peer is never
/// trusted. `head_only` applies just the revision-1 head types
/// (`dm_sync::is_dm_sync_head_type`: delegation, vault, settings, DM key
/// envelopes — all order-independent; a cancelled fanout sibling's first
/// page, round-1 audit N7) and skips the rest uncounted. Logs carry the
/// peer and message type, never a conversation.
pub(crate) fn tally_dm_sync_envelopes(
    router: &MessageRouter,
    storage: &Storage,
    wallet: &str,
    envelopes: Vec<Vec<u8>>,
    deletion_min_ts: u64,
    head_only: bool,
    peer: &PeerId,
) -> DmSyncTally {
    use crate::messages::envelope::Envelope;
    let mut t = DmSyncTally::default();
    for env_bytes in envelopes {
        let msg_type = rmp_serde::from_slice::<Envelope>(&env_bytes).ok().map(|e| e.msg_type);
        if head_only && !msg_type.is_some_and(|m| dm_sync::is_dm_sync_head_type(m as u8)) {
            continue;
        }
        match dm_sync::dm_envelope_fit(storage, wallet, &env_bytes) {
            dm_sync::DmSyncFit::Fits => {}
            dm_sync::DmSyncFit::Neutral => {
                t.neutral += 1;
                continue;
            }
            dm_sync::DmSyncFit::Foreign => {
                if msg_type.is_some_and(|m| dm_sync::is_dm_sync_v1_type(m as u8)) {
                    warn!(peer = %peer, msg_type = ?msg_type, "dm-sync: envelope outside the requested wallet's scope dropped");
                }
                t.dropped += 1;
                continue;
            }
        }
        let is_deletion = is_deletion_request(&env_bytes);
        match deletion_request_fit(storage, &env_bytes, DeletionScope::Dm, deletion_min_ts) {
            DeletionFit::Fits => {}
            DeletionFit::Neutral => {
                t.neutral += 1;
                continue;
            }
            DeletionFit::Malformed => {
                warn!(peer = %peer, "dm-sync: malformed deletion request dropped");
                t.dropped += 1;
                continue;
            }
        }
        match router.process_synced_message(&env_bytes) {
            // Pending-only / policy-refused DeletionRequest:
            // neither progress nor a fault (W1/W4); an Invalid
            // one is warned below.
            RouteResult::Accepted { .. } if is_deletion && pending_only_deletion(storage, &env_bytes) => t.neutral += 1,
            RouteResult::Rejected(_) if is_deletion => t.neutral += 1,
            RouteResult::Accepted { .. } | RouteResult::Duplicate => t.admitted += 1,
            // G4 (l2-node 0.153.0, round-1 audit N1): only the refusals an
            // honest responder can cause on a fresh node are neutral (see
            // `dm_sync::is_neutral_dm_sync_refusal`); every other warns.
            RouteResult::Rejected(reason) if dm_sync::is_neutral_dm_sync_refusal(storage, &env_bytes, &reason) => {
                debug!(peer = %peer, msg_type = ?msg_type, reason = %reason, "dm-sync: envelope refused by router (neutral)");
                t.neutral += 1;
            }
            RouteResult::Rejected(reason) | RouteResult::Invalid(reason) => {
                warn!(peer = %peer, reason = %reason, "dm-sync: envelope rejected by router");
            }
            // Key-epoch arbitration loss (0.143.0): a sync-path rejection
            // (channel scope only — dm-sync carries DM scope).
            RouteResult::KeyConflict(_) => {}
            RouteResult::PowRequired { .. } => {}
        }
    }
    t
}

/// How often `NetworkService` refreshes the shared `MeshStatsSnapshot`.
/// Short enough that an operator running `watch -n5
/// 'curl /admin/network/mesh-stats'` sees fresh data every other
/// poll; long enough that the periodic gossipsub introspection
/// doesn't compete with the publish hot path.
pub const MESH_STATS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Result delivered back to the snapshot client for one outbound request.
pub type SnapshotClientResult = Result<self::snapshot::SnapshotResponse, SnapshotClientError>;

/// Error variants surfaced to the snapshot client. Cheap to construct, no I/O.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SnapshotClientError {
    #[error("snapshot outbound failure: {0}")]
    OutboundFailure(String),
    #[error("network task dropped before response arrived")]
    Cancelled,
}

/// Command sent from the snapshot-client task to the network event loop.
///
/// The bootstrap orchestrator runs as a separate task (so the event loop
/// stays responsive to gossip/sync/identify). It dispatches snapshot
/// requests through this channel and receives responses via the embedded
/// `oneshot::Sender`. See `network::snapshot_client::ClientHandle`.
pub enum SnapshotClientCommand {
    /// Send an outbound snapshot request to a specific peer.
    SendRequest {
        peer: PeerId,
        request: self::snapshot::SnapshotRequest,
        reply: tokio::sync::oneshot::Sender<SnapshotClientResult>,
    },
    /// List PeerIds of currently connected peers (the orchestrator filters
    /// down to snapshot-capable ones based on `NodeAnnouncement`).
    ListConnectedPeers {
        reply: tokio::sync::oneshot::Sender<Vec<PeerId>>,
    },
}

impl NetworkService {
    /// Create and start the network service.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        config: &Config,
        storage: Storage,
        identity: IdentityResolver,
        keypair: libp2p::identity::Keypair,
        notification_engine: Option<Arc<NotificationEngine>>,
        peer_count: Arc<AtomicU32>,
        signing_key: ed25519_dalek::SigningKey,
        node_id: String,
        connected_peers: Arc<RwLock<HashMap<String, ConnectedPeerInfo>>>,
        counters: Arc<NetworkCounters>,
        snapshot_cache: SharedSnapshotCache,
        snapshot_client_rx: tokio::sync::mpsc::UnboundedReceiver<SnapshotClientCommand>,
        identify_success_count: Arc<AtomicU64>,
        sc_added_peer_ids: Arc<RwLock<HashSet<PeerId>>>,
        publish_failure_counters: mesh_stats::PublishFailureCounters,
        mesh_stats: mesh_stats::SharedMeshStats,
        alert_event_tx: Option<crate::notifications::alerts::AlertEventSender>,
        backfill_config: crate::config::BackfillConfig,
        dm_config: crate::config::DmConfig,
        identity_resync_config: crate::config::IdentityResyncConfig,
        private_channel_sync_config: crate::config::PrivateChannelSyncConfig,
    ) -> Result<Self> {
        // Clone before move — the presence subsystem needs its own
        // handle to sign outbound records. libp2p `Keypair` is cheap
        // to clone (internally `Arc`-backed for Ed25519).
        let keypair_for_presence = keypair.clone();
        // Same, for signing outbound Hot Topics digests (spec 3 §3.15).
        let hot_topics_keypair = keypair.clone();
        let mut swarm = behaviour::build_swarm(config, keypair)
            .context("building libp2p swarm")?;

        // Listen on configured port (QUIC primary, TCP fallback)
        let quic_addr: Multiaddr = format!(
            "/ip4/0.0.0.0/udp/{}/quic-v1",
            config.network.listen_port
        )
        .parse()
        .context("parsing QUIC listen address")?;

        let tcp_addr: Multiaddr = format!(
            "/ip4/0.0.0.0/tcp/{}",
            config.network.listen_port
        )
        .parse()
        .context("parsing TCP listen address")?;

        swarm
            .listen_on(quic_addr.clone())
            .context("listening on QUIC")?;
        swarm
            .listen_on(tcp_addr.clone())
            .context("listening on TCP")?;

        // Advertise our PUBLIC external address(es) to libp2p (audit follow-up
        // 2026-06-08). Without this the swarm only knows its `0.0.0.0`-expanded
        // LOCAL addresses (127.0.0.1, docker bridge, LAN) and leaks those via
        // Identify — peers then dial private addresses (WrongPeerId / dialing
        // themselves) and never form a stable, mutually-reachable connection,
        // so gossipsub never meshes and `NodeAnnouncement`s don't propagate
        // (peers show `api_endpoint: null`). We derive the routable address
        // from the SAME source as the on-chain metadata (`[api] public_url` +
        // `[network] listen_port`) and strip the `/p2p/<id>` suffix that
        // `add_external_address` doesn't want.
        {
            let local_peer_id = swarm.local_peer_id().to_base58();
            let (ext_multiaddrs, _) = crate::api::admin::compute_effective_multiaddrs(
                &config.anchoring.metadata,
                config.network.listen_port,
                config.api.public_url.as_deref(),
                &local_peer_id,
            );
            for ma in &ext_multiaddrs {
                let base = ma.split("/p2p/").next().unwrap_or(ma);
                match base.parse::<Multiaddr>() {
                    Ok(addr) => {
                        info!(addr = %addr, "Advertising external address to libp2p");
                        swarm.add_external_address(addr);
                    }
                    Err(e) => {
                        warn!(multiaddr = %base, error = %e, "Skipping unparseable external multiaddr");
                    }
                }
            }
        }

        // Inbound onion listen (spec 13 §6.4, l2-node 0.46.9+). When
        // the operator runs an external Tor daemon with a
        // HiddenServicePort directive forwarding to
        // 127.0.0.1:<listen_onion_port>, we open an extra loopback TCP
        // listener so the forwarded traffic terminates in our swarm
        // and goes through the standard Noise/yamux pipeline.
        //
        // The bind is loopback-only — the kernel's port is not exposed
        // on any external interface. Inbound traffic comes exclusively
        // from the Tor daemon's hidden-service forward (which the
        // operator configured to point here). Crucially, this means
        // even if the loopback address is wrong (e.g., Tor configured
        // to forward to a non-loopback port the operator typed by
        // mistake), the listener does NOT accept clearnet connections
        // — the misconfigured Tor service is what would carry them.
        if config.network.tor.enabled
            && !config.network.tor.listen_onion_hostname.is_empty()
            && config.network.tor.listen_onion_port != 0
        {
            let onion_local_addr: Multiaddr = format!(
                "/ip4/127.0.0.1/tcp/{}",
                config.network.tor.listen_onion_port
            )
            .parse()
            .context("parsing onion-inbound loopback listen address")?;
            match swarm.listen_on(onion_local_addr.clone()) {
                Ok(_) => info!(
                    onion_hostname = %config.network.tor.listen_onion_hostname,
                    loopback = %onion_local_addr,
                    "Onion inbound listener up (Tor hidden service forwards here)"
                ),
                Err(e) => warn!(
                    onion_hostname = %config.network.tor.listen_onion_hostname,
                    loopback = %onion_local_addr,
                    error = %e,
                    "Onion inbound listen failed; continuing without onion inbound"
                ),
            }
        }

        info!(
            quic = %quic_addr,
            tcp = %tcp_addr,
            onion_enabled = config.network.tor.enabled,
            "Network listening"
        );

        // Connect to bootstrap nodes and add them to Kademlia.
        // Peer IDs are accumulated into `config_peer_ids` for spec 13
        // §4.1 discovery-source classification — any Identify::Received
        // matching one of these PeerIds is tagged `config` tier.
        let mut bootstrap_addrs = Vec::new();
        let mut config_peer_ids: HashSet<PeerId> = HashSet::new();
        for addr_str in &config.network.bootstrap_nodes {
            match addr_str.parse::<Multiaddr>() {
                Ok(addr) => {
                    // Extract peer ID from multiaddr (the /p2p/<peer_id> component)
                    let peer_id = addr.iter().find_map(|proto| {
                        if let libp2p::multiaddr::Protocol::P2p(id) = proto {
                            Some(id)
                        } else {
                            None
                        }
                    });

                    // Add to Kademlia routing table so DHT bootstrap can find peers
                    if let Some(pid) = peer_id {
                        // Strip /p2p/ from addr for Kademlia (it wants transport-only addrs)
                        let transport_addr: Multiaddr = addr
                            .iter()
                            .filter(|p| !matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
                            .collect();
                        swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&pid, transport_addr);
                        config_peer_ids.insert(pid);
                    }

                    if let Err(e) = swarm.dial(addr.clone()) {
                        warn!(addr = %addr, error = %e, "Failed to dial bootstrap node");
                    } else {
                        info!(addr = %addr, "Dialing bootstrap node");
                    }
                    bootstrap_addrs.push(addr);
                }
                Err(e) => {
                    warn!(addr = %addr_str, error = %e, "Invalid bootstrap node address");
                }
            }
        }

        // Snapshot PEER_DIRECTORY peer IDs for the `book` discovery-source
        // tier (spec 13 §4.1). One-shot at startup — peers persisted later
        // by sc_discovery this session do NOT belong to the book tier;
        // they belong to whichever tier put them there. Bounded by
        // PEER_DIRECTORY's own 256-entry cap so the HashSet stays small.
        let startup_book_peer_ids: HashSet<PeerId> = storage
            .prefix_iter_cf(
                crate::storage::schema::cf::PEER_DIRECTORY,
                b"pa:",
                256,
            )
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, _v)| {
                // Key format: `pa:<peer_id_str>`. Strip prefix and parse.
                let suffix = k.strip_prefix(b"pa:")?;
                let s = std::str::from_utf8(suffix).ok()?;
                s.parse::<PeerId>().ok()
            })
            .collect();
        debug!(
            count = startup_book_peer_ids.len(),
            config_count = config_peer_ids.len(),
            "Discovery-source snapshots captured (spec 13 §4.1)"
        );

        // Create topic manager and subscribe to default topics
        let mut topics = TopicManager::new(config.network_id());
        topics.subscribe_defaults(&mut swarm);

        // Presence-gossip subsystem (spec 13 §10, l2-node 0.48.0+).
        // Build the manager (parses denylist, computes self-PeerId,
        // decides broadcast vs subscribe-only based on public_url) ONLY
        // when the operator opted in. Disabled-by-default → zero cost
        // for nodes that haven't opted in.
        let (presence_manager, presence_topic_hash, presence_validation_tx, presence_validation_rx) =
            if config.network.presence.enabled {
                topics.subscribe_presence(&mut swarm);
                let topic_str = gossip::topic_presence(config.network_id());
                let topic_hash = gossip::topic_hash(&topic_str);
                let mgr = presence::PresenceManager::new(
                    config.network_id().to_string(),
                    &config.network.presence,
                    keypair_for_presence,
                    config.api.public_url.clone(),
                )
                .context("constructing PresenceManager")?;
                info!(
                    topic = %topic_str,
                    broadcasting = mgr.broadcasting(),
                    "presence-gossip enabled (spec 13 §10)"
                );
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                (Some(Arc::new(mgr)), Some(topic_hash), Some(tx), Some(rx))
            } else {
                // Keypair_for_presence is dropped here, freeing its Arc
                // reference. The default-off path is zero-cost.
                drop(keypair_for_presence);
                (None, None, None, None)
            };

        // Create message router for P2P message processing (no PoW for gossip)
        let router = MessageRouter::new(
            storage.clone(),
            identity,
            None,
            config.network_id().to_string(),
            dm_config.max_stored_messages_per_recipient,
            counters.clone(),
            config.api.rate_limits.clone(),
        )
        .with_hot_topics_config(config.hot_topics.clone())
        // Security-audit finding (2026-10-06): this network-layer router
        // handles EVERY gossip/reconcile/private-channel-sync/news/dm/
        // identity-sync ingest path — without this, it silently used
        // `ChannelVerifyConfig::default()` regardless of what the
        // operator configured, so the `require_private_id_derivation`
        // escape hatch (meant to unblock a legacy channel's federation)
        // affected only the API-layer router's `create_channel`/
        // `federate_channel` handlers, leaving gossip/backfill of the
        // SAME channel still rejecting it — with nothing in the logs
        // explaining the inconsistency. Fails toward MORE strict by
        // default (not a security hole on its own), but the escape
        // hatch must actually reach every path that evaluates it.
        .with_channel_verify_config(config.channel_verify.clone());

        let public_url = config.api.public_url.clone();

        // Hot Topics aggregator (spec 3 §3.9). Constructed unconditionally —
        // the config's `enabled` flag makes every method a cheap no-op when
        // off — and shared with the REST layer via `hot_topics()`.
        let hot_topics = Arc::new(hot_topics::HotTopicsAggregator::new(
            storage.clone(),
            config.hot_topics.clone(),
            config.network_id().to_string(),
        ));
        let network_topic_hash =
            gossip::topic_hash(&gossip::topic_network(config.network_id()));

        let snapshot_serve_enabled = config.snapshot.serve_enabled;
        // Clamp to [1, 4096] — config can't disable the semaphore entirely
        // (we still want a backstop) and shouldn't request millions of permits.
        let snapshot_permits = config
            .snapshot
            .serve_max_concurrent_requests
            .clamp(1, 4096) as usize;
        let snapshot_chunk_semaphore = Arc::new(tokio::sync::Semaphore::new(snapshot_permits));
        // Off-loop backfill response builds → event loop (round 4). Unbounded
        // channel, but at most `MAX_CONCURRENT_RESPONDER_BUILDS` +
        // `MAX_CONTINUATION_BUILD_WAITERS` items can ever be in it: each
        // carries its build (or waiter) slot, released only after the loop
        // has sent the response.
        let (deferred_response_tx, deferred_response_rx) = tokio::sync::mpsc::unbounded_channel();
        // Private-channel lifecycle (l2-node 0.149.0): the storage layer
        // reports every lifecycle-row change here, whichever path caused it.
        // Only the FIRST service built on a database owns the notifier (one
        // per process in production); a later one keeps `None` and relies on
        // its backstop pass.
        let lifecycle_rx = {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            storage.set_channel_lifecycle_notifier(tx).then_some(rx)
        };
        let (lifecycle_scan_tx, lifecycle_scan_rx) = tokio::sync::mpsc::unbounded_channel();
        // l2-node 0.141.0: rolling responder budgets + requester attempt
        // throttles (see `budget`'s module doc).
        let reconcile_budget = budget::Gcra::new(
            backfill_config.total_envelopes_cap as u64,
            backfill_config.total_envelopes_refill_per_hour,
        );
        let reconcile_throttle = budget::AttemptThrottle::new(
            budget::MAX_THROTTLE_KEYS,
            Duration::from_secs(backfill_config.retry_backoff_max_minutes.saturating_mul(60)),
            Duration::from_secs(backfill_config.in_sync_recheck_minutes.saturating_mul(60)),
        );
        let private_channel_sync_budget = budget::Gcra::new(
            private_channel_sync_config.responder_budget_burst,
            private_channel_sync_config.responder_budget_refill_per_hour,
        );
        // l2-node 0.151.0: news / dm / identity-sync responder budgets.
        let news_sync_budget = budget::Gcra::new(
            backfill_config.news_responder_budget_burst,
            backfill_config.news_responder_budget_refill_per_hour,
        );
        let dm_sync_budget = budget::Gcra::new(
            dm_config.sync_responder_budget_burst,
            dm_config.sync_responder_budget_refill_per_hour,
        );
        let identity_sync_budget = budget::Gcra::new(
            identity_resync_config.responder_budget_burst,
            identity_resync_config.responder_budget_refill_per_hour,
        );
        let private_channel_sync_throttle = budget::AttemptThrottle::new(
            budget::MAX_THROTTLE_KEYS,
            Duration::from_secs(private_channel_sync_config.retry_backoff_max_minutes.saturating_mul(60)),
            Duration::from_secs(private_channel_sync_config.in_sync_recheck_minutes.saturating_mul(60)),
        );

        Ok(Self {
            swarm,
            topics,
            router,
            storage,
            notification_engine,
            peer_count,
            signing_key,
            node_id,
            public_url,
            connected_peers,
            peer_node_ids: HashMap::new(),
            counters,
            bootstrap_addrs,
            reconnect_queue: Vec::new(),
            known_peer_addrs: HashMap::new(),
            snapshot_cache,
            snapshot_serve_enabled,
            snapshot_chunk_semaphore,
            snapshot_client_rx,
            pending_snapshot_requests: HashMap::new(),
            identify_success_count,
            startup_book_peer_ids,
            config_peer_ids,
            sc_added_peer_ids,
            publish_failure_counters,
            mesh_stats,
            alert_event_tx,
            backfill_config,
            reconcile_limits: Arc::new(reconcile::ResponderLimits::default()),
            reconcile_budget,
            reconcile_throttle,
            pending_reconcile_requests: HashMap::new(),
            reconcile_triggered: HashSet::new(),
            pending_reconcile_comparisons: HashMap::new(),
            reconcile_meta_followup_at: HashMap::new(),
            reconcile_meta_resume: HashMap::new(),
            peer_reconcile_health: HashMap::new(),
            sync_limits: Arc::new(reconcile::ResponderLimits::default()),
            pending_sync_requests: HashMap::new(),
            identity_sync_limits: Arc::new(identity_sync::IdentityResponderLimits::new(
                budget::MAX_TRACKED_RESPONDER_KEYS,
            )),
            identity_sync_budget,
            pending_identity_sync_requests: HashMap::new(),
            identity_sync_triggered: HashSet::new(),
            identity_sync_triggered_order: std::collections::VecDeque::new(),
            news_sync_limits: Arc::new(news_sync::NewsResponderLimits::new(budget::MAX_TRACKED_RESPONDER_KEYS)),
            news_sync_budget,
            pending_news_sync_requests: HashMap::new(),
            last_news_sync: None,
            dm_config,
            observed_trigger_budget: identity_resync_config.max_observed_triggers_per_interval,
            backfill_author_trigger_budget: identity_resync_config.max_observed_triggers_per_interval,
            identity_resync_config,
            dm_sync_limits: Arc::new(dm_sync::DmResponderLimits::new(budget::MAX_TRACKED_RESPONDER_KEYS)),
            dm_sync_budget,
            pending_dm_sync_requests: HashMap::new(),
            dm_sync_cancelled_siblings: HashMap::new(),
            dm_backfill_triggered: HashSet::new(),
            wallet_claims: HashMap::new(),
            local_dm_users_seen: HashMap::new(),
            private_channel_sync_config,
            private_channel_sync_limits: Arc::new(private_channel_sync::PrivateChannelSyncResponderLimits::default()),
            private_channel_sync_budget,
            private_channel_sync_throttle,
            responder_build_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_RESPONDER_BUILDS)),
            continuation_wait_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONTINUATION_BUILD_WAITERS)),
            deferred_response_tx,
            deferred_response_rx: Some(deferred_response_rx),
            pending_private_channel_sync_requests: HashMap::new(),
            private_channel_sync_triggered: HashSet::new(),
            private_channel_sync_wallet_claims: HashMap::new(),
            lifecycle_unsubscribed: HashSet::new(),
            lifecycle_rx,
            remote_subscriber_walks: 0,
            lifecycle_check_interval_secs: config.private_channels.lifecycle_check_interval_secs,
            lifecycle_dirty: HashSet::new(),
            lifecycle_unsub_cursor: 0,
            lifecycle_scan_cursor: Vec::new(),
            lifecycle_scan_pending: 0,
            lifecycle_scan_in_flight: false,
            lifecycle_scan_tx,
            lifecycle_scan_rx: Some(lifecycle_scan_rx),
            presence_manager,
            presence_topic_hash,
            hot_topics,
            network_topic_hash,
            hot_topics_keypair,
            presence_initial_broadcast_done: false,
            presence_validation_tx,
            presence_validation_rx,
            // ≤64 concurrent presence-record Ed25519 verifies (audit W5).
            presence_verify_sem: Arc::new(tokio::sync::Semaphore::new(64)),
            gossip_rate_limiter: HashMap::new(),
            gossip_app_score: HashMap::new(),
            peer_directions: HashMap::new(),
        })
    }

    /// Classify a connected peer by which bootstrap tier dialed it
    /// this session (spec 13 §4.1).
    ///
    /// Precedence — `config` > `book` > `sc` > `runtime`. Reasoning:
    ///   - `config` is the operator's explicit intent and the most
    ///     stable label across sessions; surface it when it applies.
    ///   - `book` is historical (carried over from a prior session);
    ///     preferred over sc when both apply because the book
    ///     supplied a working entry first.
    ///   - `sc` is the on-chain fallback for this session.
    ///   - `runtime` covers everything else (DHT, mDNS, inbound).
    fn classify_discovery_source(&self, peer_id: &PeerId) -> crate::api::state::DiscoverySource {
        use crate::api::state::DiscoverySource;
        if self.config_peer_ids.contains(peer_id) {
            return DiscoverySource::Config;
        }
        if self.startup_book_peer_ids.contains(peer_id) {
            return DiscoverySource::Book;
        }
        // sc_added_peer_ids is shared with sc_discovery — read lock is
        // held only for the contains() call. Lock poisoning is
        // tolerated by falling through to runtime; corruption-free
        // operation of this set is not a correctness requirement.
        if let Ok(sc_set) = self.sc_added_peer_ids.read() {
            if sc_set.contains(peer_id) {
                return DiscoverySource::Sc;
            }
        }
        DiscoverySource::Runtime
    }

    /// Get the local peer ID.
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Return a shared handle to the presence manager — used by
    /// `node.rs` to wire the manager into `AppState` for the
    /// `/api/v1/network/presence*` REST handlers. `None` when
    /// `[network.presence] enabled = false`.
    /// Shared handle to the Hot Topics aggregator (spec 3 §3.9). Cloned into
    /// `AppState` so `GET /api/v1/news/hot-topics` serves the same merged
    /// view this service maintains.
    pub fn hot_topics(&self) -> Arc<hot_topics::HotTopicsAggregator> {
        self.hot_topics.clone()
    }

    pub fn presence_manager(&self) -> Option<Arc<presence::PresenceManager>> {
        self.presence_manager.clone()
    }

    /// Subscribe to a channel's GossipSub topic.
    ///
    /// **Channel-history backfill trigger (spec 1, l2-node 0.47.0+).**
    /// If `[backfill] enabled` AND the channel's backfill has never
    /// reached natural completion (or completed longer ago than
    /// `channel_catchup_interval_hours` — see `maybe_trigger_backfill`)
    /// AND we have not already triggered reconciliation for this
    /// channel in the current process, the trigger fires: we pick up
    /// to `[backfill] fanout` candidate peers (deprioritizing, never
    /// excluding, any currently-flagged-stale ones — l2-node 0.137.0)
    /// from the gossip mesh (falling back to SC-active nodes if mesh
    /// is sparse) and send each a `ReconcileRequest`. Rather than
    /// racing to whichever answers first, we compare their first-page
    /// responses and commit to whoever reported the most — see
    /// `finalize_reconcile_comparison`.
    pub fn subscribe_channel(&mut self, channel_id: u64) {
        self.topics
            .subscribe_channel(&mut self.swarm, channel_id);
        self.maybe_trigger_backfill(channel_id);
    }

    /// Subscribe to a user's DM topic.
    pub fn subscribe_dm(&mut self, address: &str) {
        self.topics
            .subscribe_dm(&mut self.swarm, address);
    }

    /// Unsubscribe from a user's DM topic (LRU eviction of a local DM user).
    pub fn unsubscribe_dm(&mut self, address: &str) {
        self.topics
            .unsubscribe_dm(&mut self.swarm, address);
    }

    /// Unsubscribe from a channel's gossip topic (private-channel lifecycle,
    /// l2-node 0.149.0). Only `reconcile_channel_lifecycle` calls this, and
    /// only for a private, unpinned channel with a lifecycle row and no
    /// private-sync session in flight.
    pub fn unsubscribe_channel(&mut self, channel_id: u64) -> bool {
        self.topics.unsubscribe_channel(&mut self.swarm, channel_id)
    }

    /// `true` while any private-channel-sync request for `channel_id` is
    /// outstanding (owner decision D7: no unsubscribe mid-session — a
    /// session replaying old removals could otherwise flap the topic).
    fn private_sync_in_flight(&self, channel_id: u64) -> bool {
        self.pending_private_channel_sync_requests
            .values()
            .any(|p| p.channel_id == channel_id)
    }

    /// Make the gossip subscription of `channel_id` match its lifecycle
    /// state (l2-node 0.149.0, `storage::channel_lifecycle`):
    ///
    /// - a public id or a pinned channel is never touched;
    /// - a lifecycle row present → unsubscribe (deferred while a private-
    ///   sync session for the channel is in flight) and remember it in
    ///   `lifecycle_unsubscribed`;
    /// - no row, but this node dropped the topic earlier → subscribe again
    ///   and ask the private-sync requester to backfill the gap for every
    ///   local member (it no-ops without a cached wallet claim; the API
    ///   path that cancelled the row sends its own trigger as well).
    ///
    /// A storage error keeps the current subscription (fail towards keep).
    /// Idempotent; driven by the storage notifier, the `channel_rx`
    /// subscribe path, private-sync completion and the backstop pass.
    fn reconcile_channel_lifecycle(&mut self, channel_id: u64) {
        if crate::messages::types::is_public_channel_id(channel_id) {
            return;
        }
        let blocked = match self.storage.lifecycle_blocks_subscription(channel_id) {
            Ok(b) => b,
            Err(e) => {
                warn!(channel_id, error = %e, "private-channel lifecycle: row read failed; keeping the subscription");
                return;
            }
        };
        let subscribed = self.topics.is_channel_subscribed(channel_id);
        if blocked {
            if subscribed {
                if self.private_sync_in_flight(channel_id) {
                    debug!(channel_id, "private-channel lifecycle: unsubscribe deferred while a private-sync session is in flight");
                    // The session's release re-applies it; the next
                    // backstop tick does too, should that be missed.
                    self.lifecycle_dirty.insert(channel_id);
                    return;
                }
                if self.unsubscribe_channel(channel_id) {
                    self.counters.inc_private_channel_unsubscribes();
                    info!(channel_id, "private-channel lifecycle: no local member left; unsubscribed the channel topic");
                }
            }
            self.lifecycle_unsubscribed.insert(channel_id);
        } else if self.lifecycle_unsubscribed.remove(&channel_id) {
            // The row is gone because the purge reaper FINISHED (or the
            // channel was deleted): the channel no longer exists here, so
            // there is nothing to re-subscribe to. A later re-federation
            // subscribes through `channel_rx` like any new channel.
            if !matches!(
                self.storage.exists_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes()),
                Ok(true)
            ) {
                debug!(channel_id, "private-channel lifecycle: channel purged; topic stays unsubscribed");
                return;
            }
            if !subscribed {
                self.subscribe_channel(channel_id);
                self.counters.inc_private_channel_resubscribes();
                info!(channel_id, "private-channel lifecycle: local member returned; re-subscribed the channel topic");
            }
            match self
                .storage
                .local_member_wallets(channel_id, crate::storage::channel_lifecycle::RESUBSCRIBE_SYNC_WALLETS)
            {
                Ok(wallets) => {
                    for wallet in wallets {
                        self.maybe_trigger_private_channel_sync(channel_id, &wallet, None, false);
                    }
                }
                Err(e) => debug!(channel_id, error = %e, "private-channel lifecycle: local-member read failed; no gap backfill triggered"),
            }
        }
    }

    /// Backstop pass (`[private_channels] lifecycle_check_interval_secs`).
    /// Never scans the lifecycle CF on the event loop:
    ///
    /// 1. re-applies the ids notified (or deferred) since the last tick and
    ///    every channel this node holds unsubscribed (point reads only —
    ///    a row that disappeared re-subscribes, a deferred unsubscribe
    ///    applies);
    /// 2. starts ONE bounded page read ([`LIFECYCLE_BACKSTOP_PAGE`] rows) of
    ///    the CF on the blocking pool from a rotating cursor; its result
    ///    (`apply_lifecycle_scan_page`) converges rows whose notification
    ///    was missed and, once a rotation completes, refreshes the
    ///    `private_channels_pending` gauge.
    fn lifecycle_backstop(&mut self) {
        self.lifecycle_backstop_tick();
        self.start_lifecycle_scan_page();
    }

    /// Step 1 of `lifecycle_backstop`: every dirty id, plus a rotating
    /// batch of at most [`LIFECYCLE_BACKSTOP_PAGE`] of the channels held
    /// unsubscribed (ascending id after `lifecycle_unsub_cursor`, wrapping),
    /// so a large unsubscribed set is never re-read whole on one tick.
    fn lifecycle_backstop_tick(&mut self) {
        let mut ids: HashSet<u64> = std::mem::take(&mut self.lifecycle_dirty);
        let cursor = self.lifecycle_unsub_cursor;
        let mut batch: Vec<u64> = self.lifecycle_unsubscribed.iter().copied().filter(|&c| c > cursor).collect();
        batch.sort_unstable();
        batch.truncate(LIFECYCLE_BACKSTOP_PAGE);
        if batch.len() < LIFECYCLE_BACKSTOP_PAGE {
            let mut head: Vec<u64> = self.lifecycle_unsubscribed.iter().copied().filter(|&c| c <= cursor).collect();
            head.sort_unstable();
            head.truncate(LIFECYCLE_BACKSTOP_PAGE - batch.len());
            batch.extend(head);
        }
        self.lifecycle_unsub_cursor = if batch.len() >= LIFECYCLE_BACKSTOP_PAGE {
            batch.last().copied().unwrap_or(0)
        } else {
            0
        };
        ids.extend(batch);
        for cid in ids {
            self.reconcile_channel_lifecycle(cid);
        }
    }

    /// Step 2 of `lifecycle_backstop`: one page read off the event loop
    /// (skipped while the previous one is still running).
    fn start_lifecycle_scan_page(&mut self) {
        if self.lifecycle_scan_in_flight {
            return;
        }
        self.lifecycle_scan_in_flight = true;
        let storage = self.storage.clone();
        let cursor = self.lifecycle_scan_cursor.clone();
        let mut guard = LifecycleScanSendGuard(Some(self.lifecycle_scan_tx.clone()));
        tokio::task::spawn_blocking(move || {
            let result = storage
                .private_channel_lifecycle_page(&cursor, LIFECYCLE_BACKSTOP_PAGE)
                .map_err(|e| e.to_string());
            guard.send(LifecycleScanPage { result });
        });
    }

    /// Apply one finished page read: reconcile every id not already held
    /// unsubscribed (those are re-applied by every tick anyway), advance the
    /// rotating cursor, and publish the pending gauge at the end of a
    /// rotation. A read error keeps the cursor (retried next tick).
    fn apply_lifecycle_scan_page(&mut self, page: LifecycleScanPage) {
        self.lifecycle_scan_in_flight = false;
        let (ids, next) = match page.result {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "private-channel lifecycle: backstop page read failed");
                return;
            }
        };
        for (cid, pending) in ids {
            self.lifecycle_scan_pending += u64::from(pending);
            if !self.lifecycle_unsubscribed.contains(&cid) {
                self.reconcile_channel_lifecycle(cid);
            }
        }
        match next {
            Some(cursor) => self.lifecycle_scan_cursor = cursor,
            None => {
                self.counters.set_private_channels_pending(self.lifecycle_scan_pending);
                self.lifecycle_scan_pending = 0;
                self.lifecycle_scan_cursor.clear();
            }
        }
    }

    /// Subscribe a channel on request (`channel_rx`: chain discovery,
    /// federate, local create/join). A private channel with a lifecycle row
    /// is NOT subscribed — otherwise any of those re-subscribes would undo
    /// the lifecycle decision — and goes through
    /// `reconcile_channel_lifecycle` instead.
    fn handle_channel_subscribe_request(&mut self, channel_id: u64) {
        match self.storage.lifecycle_blocks_subscription(channel_id) {
            Ok(true) => {
                debug!(channel_id, "channel subscribe request: pending private-channel cleanup, not subscribing");
                self.reconcile_channel_lifecycle(channel_id);
            }
            // A read error falls back to today's behavior: subscribe.
            Ok(false) | Err(_) => {
                self.lifecycle_unsubscribed.remove(&channel_id);
                self.subscribe_channel(channel_id);
                info!(channel_id, "Auto-subscribed to channel topic (chain discovery)");
            }
        }
    }

    /// Startup: subscribe every channel in `CHANNELS` (up to 100k) except a
    /// private channel with a lifecycle row, then every pinned channel
    /// (always — pinned channels are never affected by the lifecycle).
    /// Returns how many stored channels were subscribed.
    pub fn subscribe_stored_channels(&mut self, pinned: &[u64]) -> u64 {
        let mut count = 0u64;
        match self.storage.prefix_iter_cf(crate::storage::schema::cf::CHANNELS, &[], 100_000) {
            Ok(entries) => {
                for (key, _) in &entries {
                    let Ok(id_bytes) = <[u8; 8]>::try_from(key.as_slice()) else { continue };
                    let channel_id = u64::from_be_bytes(id_bytes);
                    match self.storage.lifecycle_blocks_subscription(channel_id) {
                        Ok(true) => {
                            self.lifecycle_unsubscribed.insert(channel_id);
                        }
                        Ok(false) | Err(_) => {
                            self.subscribe_channel(channel_id);
                            count += 1;
                        }
                    }
                }
            }
            Err(e) => warn!(error = %e, "Failed to load existing channels for GossipSub"),
        }
        if !self.lifecycle_unsubscribed.is_empty() {
            info!(
                count = self.lifecycle_unsubscribed.len(),
                "Not subscribing private channels pending local cleanup (no local member)"
            );
        }
        // Pinned channels (may overlap with above; subscribe_channel is
        // idempotent). Never in `lifecycle_unsubscribed` — except one whose
        // purge started before the pin and is still running (it finishes;
        // `lifecycle_blocks_subscription` keeps it off meanwhile).
        for &channel_id in pinned {
            if matches!(self.storage.private_channel_purge_in_progress(channel_id), Ok(true)) {
                self.lifecycle_unsubscribed.insert(channel_id);
                continue;
            }
            self.lifecycle_unsubscribed.remove(&channel_id);
            self.subscribe_channel(channel_id);
        }
        count
    }

    /// Register `wallet` as a local DM user (offline store-and-forward Phase 1).
    ///
    /// Called when a wallet authenticates to this node (WS/REST). Persists it to
    /// `LOCAL_DM_USERS` so the node re-subscribes to its DM gossip topic on every
    /// restart — receiving that user's cross-node DMs even while they are OFFLINE
    /// — then subscribes immediately, evicts the least-recently-active user if
    /// over the cap, and lazily fires a one-time dm-sync backfill for missed DMs.
    fn register_local_dm_user(&mut self, wallet: &str, wallet_claim: Option<dm_sync::WalletAuthClaim>) {
        // How often we re-persist `last_active_ms` for an already-known wallet.
        // The per-REST-request path calls this on every request; the throttle
        // keeps it O(1) most of the time while still letting LRU eviction see
        // genuine recency rather than only first-seen.
        const REFRESH_THROTTLE_MS: u64 = 5 * 60 * 1000;
        const MAX_SEEN: usize = 100_000;

        let now = now_ms();
        let due = match self.local_dm_users_seen.get(wallet) {
            Some(&last_persist) => now.saturating_sub(last_persist) >= REFRESH_THROTTLE_MS,
            None => true,
        };

        if due {
            // Bound the throttle map; on overflow clear it (next call re-does the
            // idempotent storage upsert — harmless).
            if self.local_dm_users_seen.len() >= MAX_SEEN {
                self.local_dm_users_seen.clear();
            }
            let key = wallet.as_bytes();

            // Upsert: preserve first_seen, refresh last_active. A storage error
            // here is non-fatal — we still subscribe so live delivery works.
            let is_new = match self.storage.get_cf(schema::cf::LOCAL_DM_USERS, key) {
                Ok(Some(existing)) => {
                    let first_seen = schema::decode_local_dm_user(&existing)
                        .map(|(f, _)| f)
                        .unwrap_or(now);
                    let _ = self.storage.put_cf(
                        schema::cf::LOCAL_DM_USERS,
                        key,
                        &schema::encode_local_dm_user(first_seen, now),
                    );
                    false
                }
                Ok(None) => {
                    let _ = self.storage.put_cf(
                        schema::cf::LOCAL_DM_USERS,
                        key,
                        &schema::encode_local_dm_user(now, now),
                    );
                    true
                }
                Err(e) => {
                    warn!(%wallet, error = %e, "register_local_dm_user: LOCAL_DM_USERS read failed; subscribing anyway");
                    false
                }
            };

            // Subscribe (idempotent in the topic layer).
            self.subscribe_dm(wallet);

            // Record BEFORE eviction so the just-registered wallet is protected
            // from being chosen as the LRU victim of its own insertion.
            self.local_dm_users_seen.insert(wallet.to_string(), now);

            // Enforce the subscription cap with LRU eviction — only when we just
            // ADDED a user (steady-state refreshes don't grow the set).
            if is_new {
                self.evict_local_dm_users_over_cap(wallet);
            }
        }

        // Lazily backfill missed DMs for this wallet, once per process (self-
        // dedups; retries on a later call if no peers were connected yet).
        self.maybe_trigger_dm_backfill(wallet, wallet_claim);
    }

    /// Evict least-recently-active local DM users until the count is within
    /// `[dm] max_local_subscriptions` (LRU on `last_active_ms`). Unsubscribes the
    /// evicted wallet's DM topic, deletes its `LOCAL_DM_USERS` row, AND drops it
    /// from the in-memory throttle map so a later re-auth re-establishes it (else
    /// the throttle would short-circuit and the user would silently stop
    /// receiving cross-node DMs until restart). `protect` is the wallet we just
    /// registered — never evict it as the victim of its own insertion. A cap of 0
    /// disables the bound (unbounded — not recommended outside tiny test fleets).
    fn evict_local_dm_users_over_cap(&mut self, protect: &str) {
        let cap = self.dm_config.max_local_subscriptions;
        if cap == 0 {
            return;
        }
        // Cap the scan so a pathological CF can't stall the network loop.
        const SCAN_CAP: usize = 200_000;
        let rows = match self
            .storage
            .prefix_iter_cf(schema::cf::LOCAL_DM_USERS, &[], SCAN_CAP)
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "evict_local_dm_users_over_cap: scan failed");
                return;
            }
        };
        if rows.len() <= cap {
            return;
        }
        // Sort ascending by last_active_ms; evict the oldest until within cap.
        let mut by_active: Vec<(u64, Vec<u8>)> = rows
            .into_iter()
            .map(|(k, v)| {
                let last = schema::decode_local_dm_user(&v).map(|(_, l)| l).unwrap_or(0);
                (last, k)
            })
            .collect();
        by_active.sort_unstable_by_key(|(last, _)| *last);
        let mut evict_n = by_active.len().saturating_sub(cap);
        for (_, key) in by_active.into_iter() {
            if evict_n == 0 {
                break;
            }
            let wallet = match std::str::from_utf8(&key) {
                Ok(w) => w.to_string(),
                Err(_) => continue,
            };
            if wallet == protect {
                continue; // never evict the wallet we just registered
            }
            self.unsubscribe_dm(&wallet);
            let _ = self.storage.delete_cf(schema::cf::LOCAL_DM_USERS, &key);
            self.local_dm_users_seen.remove(&wallet);
            debug!(%wallet, "evicted least-recently-active local DM user (over cap)");
            evict_n -= 1;
        }
    }

    /// DM retention reaper entry point (audit final pre-mainnet W11). Runs 4
    /// (3 before l2-node 0.153.0) independent, self-contained sweeps, each keyed off timestamp bytes
    /// already present verbatim in the row being examined — never by
    /// re-deriving one CF's delete-key from another CF's decoded content
    /// (identity resolution can change over the retention window; that class
    /// of bug has bitten this campaign before, e.g. W6's
    /// channel_id-from-untrusted-field). `retention_days == 0` means
    /// "unlimited" — disables all passes, matching the pre-existing
    /// documented config semantic.
    fn reap_expired_dms(&mut self) {
        if self.dm_config.retention_days == 0 {
            return;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cutoff_ms = now_ms.saturating_sub(
            self.dm_config
                .retention_days
                .saturating_mul(24 * 3600 * 1000),
        );
        self.reap_dm_msg_shaped_cf(
            schema::cf::DM_MESSAGES,
            schema::state_keys::DM_REAP_CURSOR_MESSAGES,
            cutoff_ms,
            true, // Pass A: also decrement the per-recipient counter
        );
        self.reap_dm_conversations(cutoff_ms);
        self.reap_dm_msg_shaped_cf(
            schema::cf::DM_EDIT_DELETE_MSGS,
            schema::state_keys::DM_REAP_CURSOR_EDIT_DELETE,
            cutoff_ms,
            false, // Pass C: edit/delete envelopes were never counted, don't decrement
        );
        // Pass D (l2-node 0.153.0, G4): DM reaction index rows and their
        // reaction envelopes (same key shape, keyed by the REACTION's ts).
        // The derived `CHAT_REACTIONS` rows stay (unchanged limitation).
        self.reap_dm_msg_shaped_cf(
            schema::cf::DM_REACTION_MSGS,
            schema::state_keys::DM_REAP_CURSOR_REACTIONS,
            cutoff_ms,
            false,
        );
    }

    /// Pass A / Pass C: reaps a `DM_MESSAGES`- or `DM_EDIT_DELETE_MSGS`-shaped
    /// CF (both keyed `conversation_id(32) ++ timestamp_be(8) ++ msg_id(32)`).
    /// For every expired row: deletes the index row itself, deletes the
    /// envelope's `MESSAGES[msg_id]` content, opportunistically deletes any
    /// `DELETION_MARKERS[msg_id]` (cheap, msg_id already in hand), and — only
    /// for Pass A (`decrement_counter`) — decrements the recipient's
    /// `DM_RECIPIENT_MSG_COUNTS` entry (paired with the increment in
    /// `MessageRouter::update_indexes`; edit/delete envelopes are never
    /// indexed into `DM_MESSAGES` so they were never counted, W6 note).
    /// The tricky key-parsing/cutoff decision is factored into the pure
    /// `plan_dm_msg_shaped_reap` (unit tested); this method is just the I/O
    /// shell around it.
    fn reap_dm_msg_shaped_cf(
        &mut self,
        cf_name: &str,
        cursor_key: &[u8],
        cutoff_ms: u64,
        decrement_counter: bool,
    ) {
        let cursor = self
            .storage
            .get_cf(schema::cf::NODE_STATE, cursor_key)
            .ok()
            .flatten()
            .unwrap_or_default();
        let rows = match self
            .storage
            .iter_cf_from(cf_name, &cursor, &[], DM_REAP_MAX_ROWS_EXAMINED)
        {
            Ok(r) => r,
            Err(e) => {
                warn!(cf = cf_name, error = %e, "reap_dm_msg_shaped_cf: scan failed");
                return;
            }
        };
        let (to_delete, next_cursor) =
            plan_dm_msg_shaped_reap(&rows, cutoff_ms, DM_REAP_BATCH_LIMIT);
        for key in &to_delete {
            let msg_id = &key[40..72];
            let _ = self.storage.delete_cf(cf_name, key);
            if decrement_counter {
                if let Ok(Some(content)) = self.storage.get_cf(schema::cf::MESSAGES, msg_id) {
                    if let Ok(envelope) = rmp_serde::from_slice::<crate::messages::envelope::Envelope>(&content) {
                        if let Ok(payload) =
                            rmp_serde::from_slice::<crate::messages::types::DirectMessagePayload>(
                                &envelope.payload,
                            )
                        {
                            let _ = self
                                .storage
                                .decrement_dm_recipient_count(payload.recipient.as_bytes());
                        }
                    }
                }
            }
            let _ = self.storage.delete_cf(schema::cf::MESSAGES, msg_id);
            let _ = self
                .storage
                .delete_cf(schema::cf::DELETION_MARKERS, msg_id);
            // l2-node 0.151.0: the verified GDPR record of a reaped DM (its
            // exact `msg_id` key) dies with it.
            let _ = self
                .storage
                .delete_cf(schema::cf::DELETION_REQUESTS, msg_id);
        }
        // Persist the cursor just past the last row this sweep looked at (or
        // wrap to the start if the CF is empty/exhausted), so the next tick
        // resumes forward progress regardless of how many rows were expired.
        match next_cursor {
            Some(nc) => {
                let _ = self.storage.put_cf(schema::cf::NODE_STATE, cursor_key, &nc);
            }
            None => {
                let _ = self.storage.delete_cf(schema::cf::NODE_STATE, cursor_key);
            }
        }
    }

    /// Pass B: reaps `DM_CONVERSATIONS`, keyed
    /// `wallet_address(variable, ≤70 bytes) ++ !timestamp_be(8) ++
    /// conversation_id(32)`. The wallet-address prefix is NOT fixed-width —
    /// the recipient-side row's prefix is `DirectMessagePayload.recipient`,
    /// an attacker-controlled field only bounded by `MAX_KLEVER_ADDRESS_LEN`
    /// (70), not guaranteed to be exactly 62 bytes like a real resolved
    /// wallet — so the wallet length is derived from the END of the key
    /// (`key.len() - 40`, the trailing `!ts(8)+conversation_id(32)` is always
    /// fixed-width), never a hardcoded offset from the start. See
    /// `plan_dm_conversations_reap` (pure, unit tested) for the actual logic.
    fn reap_dm_conversations(&mut self, cutoff_ms: u64) {
        let cursor = self
            .storage
            .get_cf(schema::cf::NODE_STATE, schema::state_keys::DM_REAP_CURSOR_CONVERSATIONS)
            .ok()
            .flatten()
            .unwrap_or_default();
        let rows = match self.storage.iter_cf_from(
            schema::cf::DM_CONVERSATIONS,
            &cursor,
            &[],
            DM_REAP_MAX_ROWS_EXAMINED,
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "reap_dm_conversations: scan failed");
                return;
            }
        };
        let (to_delete, next_cursor) =
            plan_dm_conversations_reap(&rows, cutoff_ms, DM_REAP_BATCH_LIMIT);
        for key in &to_delete {
            let _ = self.storage.delete_cf(schema::cf::DM_CONVERSATIONS, key);
        }
        match next_cursor {
            Some(nc) => {
                let _ = self.storage.put_cf(
                    schema::cf::NODE_STATE,
                    schema::state_keys::DM_REAP_CURSOR_CONVERSATIONS,
                    &nc,
                );
            }
            None => {
                let _ = self.storage.delete_cf(
                    schema::cf::NODE_STATE,
                    schema::state_keys::DM_REAP_CURSOR_CONVERSATIONS,
                );
            }
        }
    }

    /// Periodic staleness-aware identity re-check (design doc "Closing the
    /// Identity-Sync Coverage Gap" §2) — closes a gap the broadened
    /// observed-author trigger (`handle_gossip_message`) cannot: that
    /// trigger is a one-shot per wallet per process lifetime
    /// (`identity_sync_triggered` dedup), so a wallet whose identity bundle
    /// looked complete when it was last pulled, but who updates it AGAIN
    /// later — via a node this one never talks to, with THAT live gossip
    /// update also missed — would otherwise stay deduped forever with
    /// nothing to ever revisit it short of a full node restart.
    ///
    /// Slow-drips through `USERS` in key order, resuming from a persisted
    /// cursor each tick — same resumable-batch shape as
    /// `reap_dm_msg_shaped_cf` above — and only ACTS (clears the dedup
    /// entry + re-triggers) on rows that still look incomplete per
    /// `identity_sync::profile_looks_incomplete_json`; most ticks on a
    /// healthy node find nothing to do. `max_retriggers_per_sweep` bounds
    /// outbound requests per tick independent of table size or how many
    /// incomplete rows a batch happens to contain (see
    /// `plan_identity_staleness_sweep`'s doc comment).
    fn sweep_identity_staleness(&mut self) {
        if !self.identity_resync_config.enabled {
            return;
        }
        // Refill the observed-author trigger's budget on every tick of this
        // interval — the two mechanisms conceptually share one cadence
        // rather than each owning a dedicated `tokio::time::interval`. This
        // runs even when the SWEEP portion below is a no-op (an empty
        // `USERS` table, or between real work), which is fine: the refill
        // is O(1) regardless.
        self.observed_trigger_budget = self.identity_resync_config.max_observed_triggers_per_interval;
        self.backfill_author_trigger_budget = self.identity_resync_config.max_observed_triggers_per_interval;
        let cursor = match self.storage.get_cf(
            schema::cf::NODE_STATE,
            schema::state_keys::IDENTITY_STALENESS_CURSOR,
        ) {
            Ok(c) => c.unwrap_or_default(),
            Err(e) => {
                warn!(
                    error = %e,
                    "sweep_identity_staleness: cursor read failed, restarting scan from the beginning"
                );
                Vec::new()
            }
        };
        let rows = match self.storage.iter_cf_from(
            schema::cf::USERS,
            &cursor,
            &[],
            self.identity_resync_config.sweep_batch_size,
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "sweep_identity_staleness: scan failed");
                return;
            }
        };
        let (candidates, next_cursor) = plan_identity_staleness_sweep(
            &rows,
            self.identity_resync_config.max_retriggers_per_sweep,
        );
        match next_cursor {
            Some(nc) => {
                if let Err(e) = self.storage.put_cf(
                    schema::cf::NODE_STATE,
                    schema::state_keys::IDENTITY_STALENESS_CURSOR,
                    &nc,
                ) {
                    warn!(error = %e, "sweep_identity_staleness: cursor write failed");
                }
            }
            None => {
                if let Err(e) = self.storage.delete_cf(
                    schema::cf::NODE_STATE,
                    schema::state_keys::IDENTITY_STALENESS_CURSOR,
                ) {
                    warn!(error = %e, "sweep_identity_staleness: cursor delete failed");
                }
            }
        }
        for wallet in candidates {
            // Force a re-trigger regardless of this session's prior dedup —
            // the row STILL looks incomplete, so whatever happened before
            // (never triggered, or triggered but the pull/apply didn't
            // actually land complete data) needs another try.
            self.identity_sync_triggered_remove(&wallet);
            self.maybe_trigger_identity_sync(wallet, identity_sync::SCOPE_ALL);
        }
    }

    /// Run the network event loop. Call this from a spawned task.
    ///
    /// Processes swarm events, routes messages to storage, and subscribes
    /// to new channel topics as they are discovered by the chain scanner.
    /// Periodically retries Kademlia bootstrap if peer count is low.
    pub async fn run(
        &mut self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        mut channel_rx: tokio::sync::mpsc::UnboundedReceiver<u64>,
        mut gossip_rx: tokio::sync::mpsc::UnboundedReceiver<GossipPublish>,
        // v0.44.0: sc_discovery sends `()` here when it persists new
        // multiaddrs from the on-chain registry. We respond by
        // running `dial_persisted_peers` out-of-cycle so SC-discovered
        // peers get dialed within seconds instead of waiting up to
        // 30s for the next periodic bootstrap tick. Spec 13 §4.3.
        mut sc_reconnect_rx: tokio::sync::mpsc::Receiver<()>,
        // P-1: the API/router task sends here when a wallet is first seen on
        // this node (login / node-switch) or a device can't be resolved, asking
        // us to lazily pull that wallet's identity bundle from peers.
        mut identity_sync_rx: tokio::sync::mpsc::UnboundedReceiver<IdentitySyncCommand>,
        // API/WS → network: subscribe a wallet's DM gossip topic on WS connect so
        // this node receives that user's cross-node DMs, optionally carrying a
        // wallet-signed dm-sync backfill authorization for this node (W5).
        mut dm_subscribe_rx: tokio::sync::mpsc::UnboundedReceiver<DmSubscribeEvent>,
        // API → network: a wallet federated a private channel to this node
        // (`federate_channel`), asking us to backfill its missed history.
        // Closes the F2 backfill gap (l2-node 0.138.0+).
        mut private_channel_sync_rx: tokio::sync::mpsc::UnboundedReceiver<PrivateChannelSyncTrigger>,
    ) {
        info!(
            peer_id = %self.swarm.local_peer_id(),
            "Network event loop started"
        );

        // Take the presence validation-outcome receiver into the loop;
        // `presence_validation_tx` (the Send half) stays on `self` so
        // `handle_presence_message` can hand it to the spawned task.
        // `None` when presence is disabled.
        let mut presence_validation_rx = self.presence_validation_rx.take();
        // Finished off-loop backfill responses (round 4). Always `Some` on
        // the first (only) `run()`; a second `run()` would park this arm.
        let mut deferred_response_rx = self.deferred_response_rx.take();
        // Private-channel lifecycle notifications (l2-node 0.149.0); `None`
        // when another service owns the notifier (tests) — the backstop
        // pass below still converges.
        let mut lifecycle_rx = self.lifecycle_rx.take();
        // Results of the backstop's off-loop page reads.
        let mut lifecycle_scan_rx = self.lifecycle_scan_rx.take();
        // Backstop pass for the lifecycle (re-applies every row: deferred
        // unsubscribes, missed notifications) + the pending gauge.
        let mut lifecycle_interval =
            tokio::time::interval(Duration::from_secs(self.lifecycle_check_interval_secs.max(1)));
        lifecycle_interval.tick().await; // skip immediate tick

        // Dial persisted peers from previous sessions (survives restart)
        self.dial_persisted_peers();

        // Re-subscribe to the DM gossip topics of the wallets this node is home
        // for (offline store-and-forward Phase 1, l2-node 0.69.0+). This runs on
        // EVERY startup so an offline user's DMs are received and stored even
        // before that user re-connects this session. Bounded by the same
        // `[dm] max_local_subscriptions` cap (we re-subscribe at most that many,
        // most-recently-active first).
        self.resubscribe_local_dm_users();

        // Periodic Kademlia bootstrap + reconnection (every 30s).
        let mut bootstrap_interval = tokio::time::interval(Duration::from_secs(30));
        bootstrap_interval.tick().await; // skip the immediate first tick

        // Periodic NodeAnnouncement (every 5 minutes) — tells other nodes
        // we exist so they can list us in /api/v1/network/nodes.
        let mut announce_interval = tokio::time::interval(Duration::from_secs(300));
        announce_interval.tick().await; // skip immediate tick

        // Reconnection check interval (every 10s) — processes the reconnect queue.
        let mut reconnect_interval = tokio::time::interval(Duration::from_secs(10));
        reconnect_interval.tick().await;

        // Reconcile first-page comparison deadline sweep (l2-node
        // 0.137.0, every 1s) — finalizes any `pending_reconcile_
        // comparisons` entry whose `deadline` has passed even if not
        // every candidate has answered yet, so one slow/dead peer can't
        // stall the others past `RECONCILE_COMPARE_WINDOW`. Tight
        // interval is cheap: this map is empty almost all the time, and
        // even at scale is bounded by concurrent in-flight triggers, not
        // by channel count.
        let mut reconcile_compare_interval = tokio::time::interval(Duration::from_secs(1));
        reconcile_compare_interval.tick().await;

        // Mesh-stats refresh (every 30s) — snapshots per-topic mesh
        // size + subscriber count into `self.mesh_stats` for the
        // `/admin/network/mesh-stats` endpoint (spec 10 §9.2,
        // l2-node 0.46.6+).
        let mut mesh_stats_interval =
            tokio::time::interval(MESH_STATS_REFRESH_INTERVAL);
        mesh_stats_interval.tick().await;

        // Presence-gossip self-broadcast cadence (spec 13 §10.5).
        // When the manager is absent (presence disabled) or non-
        // broadcasting (no public URL), the interval still ticks but
        // `publish_presence_self_record` exits early. Default 6h.
        let presence_interval_secs = self
            .presence_manager
            .as_ref()
            .map(|m| m.rebroadcast_interval_secs())
            .unwrap_or(21_600);
        let mut presence_interval =
            tokio::time::interval(Duration::from_secs(presence_interval_secs.max(1)));
        // Skip the immediate first tick — the initial broadcast fires
        // on mesh stabilization, not at boot.
        presence_interval.tick().await;

        // DM retention reaper cadence (audit final pre-mainnet W11, l2-node
        // 0.101.0+). Own interval, not piggybacked on `mesh_stats_interval`
        // like W10's cheap prune — a reap sweep does real cross-CF deletion
        // work and shouldn't compete with mesh-stats' tight 30s budget.
        let mut dm_reap_interval =
            tokio::time::interval(Duration::from_secs(self.dm_config.reap_interval_secs.max(1)));
        dm_reap_interval.tick().await; // skip immediate tick

        // Identity-staleness sweep cadence (design doc "Closing the
        // Identity-Sync Coverage Gap" §2) — also the refill cadence for the
        // observed-author trigger's request budget (`observed_trigger_budget`),
        // since the two mechanisms share one interval rather than each
        // owning a dedicated one. Own interval, same reasoning as the DM
        // reaper above — a `USERS`-table scan shouldn't compete with
        // mesh-stats' tight 30s budget, and its cadence (data-completeness
        // convergence) is unrelated to either.
        //
        // `None` (not a 1-second interval via `.max(1)`) when
        // `sweep_interval_secs == 0` — Code Audit finding: a `.max(1)` here
        // would wake this loop every second forever just to immediately
        // return, for the life of the process, on the documented "0 means
        // disabled" config value. Mirrors the existing `None =>
        // std::future::pending().await` idiom used for the disabled-presence
        // path above.
        let mut identity_staleness_interval = if self.identity_resync_config.sweep_interval_secs > 0 {
            let mut iv = tokio::time::interval(Duration::from_secs(
                self.identity_resync_config.sweep_interval_secs,
            ));
            iv.tick().await; // skip immediate tick
            Some(iv)
        } else {
            None
        };

        // Hot Topics digest publish cadence (spec 3 §3.9). First publish is
        // jittered `0..=publish_jitter_secs` past one full interval to avoid a
        // fleet-wide thundering herd after a coordinated restart. The arm is a
        // no-op when `[hot_topics] enabled`/`mesh_enabled` is false.
        let ht_cfg = self.hot_topics.config().clone();
        let ht_period = Duration::from_secs(ht_cfg.publish_interval_secs.max(1));
        let ht_jitter = if ht_cfg.publish_jitter_secs > 0 {
            // `publish_jitter_secs` is config-clamped to <= 3600, so `+ 1`
            // cannot overflow and the modulus is never 0.
            Duration::from_secs(
                rand::random::<u64>() % ht_cfg.publish_jitter_secs.saturating_add(1),
            )
        } else {
            Duration::ZERO
        };
        let mut hot_topics_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + ht_period + ht_jitter,
            ht_period,
        );

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event);
                }
                Some(cmd) = identity_sync_rx.recv() => {
                    self.maybe_trigger_identity_sync(cmd.wallet, cmd.scopes);
                }
                Some(event) = dm_subscribe_rx.recv() => {
                    // A wallet authenticated here. Persist it as a local DM user
                    // (so we re-subscribe on restart and receive its DMs while
                    // offline), subscribe now, enforce the LRU cap, and lazily
                    // backfill any DMs missed while this node was down (gated
                    // on a wallet-signed authorization, audit W5).
                    self.register_local_dm_user(&event.wallet, event.wallet_claim);
                    debug!(wallet = %event.wallet, "Registered local DM user + subscribed to DM gossip topic");
                }
                Some(event) = private_channel_sync_rx.recv() => {
                    // A wallet federated a private channel here — lazily
                    // backfill its missed history (gated on a wallet-signed
                    // authorization, mirroring dm-sync's audit-W5 gate).
                    match event.channel_id {
                        Some(channel_id) => {
                            let bypass = event.wallet_claim.is_some();
                            self.maybe_trigger_private_channel_sync(channel_id, &event.wallet, event.wallet_claim, bypass);
                        }
                        None => self.refresh_private_channel_sync_claim(&event.wallet, event.wallet_claim),
                    }
                }
                Some(channel_id) = channel_rx.recv() => {
                    // Code Audit W2 (0.47.0): route chain-discovered
                    // channels through `Self::subscribe_channel` (not
                    // the bare `Topics::subscribe_channel`) so the
                    // cold-join backfill trigger fires. The trigger is
                    // idempotent via `reconcile_triggered`, so
                    // duplicate calls are safe. l2-node 0.149.0: a private
                    // channel pending local cleanup is not re-subscribed
                    // here (that would undo the lifecycle decision).
                    self.handle_channel_subscribe_request(channel_id);
                }
                Some(channel_id) = async {
                    match lifecycle_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.reconcile_channel_lifecycle(channel_id);
                    // Re-applied by the next backstop tick too (a deferred
                    // or failed reconcile must not depend on a full scan).
                    self.lifecycle_dirty.insert(channel_id);
                }
                Some(page) = async {
                    match lifecycle_scan_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.apply_lifecycle_scan_page(page);
                }
                _ = lifecycle_interval.tick() => {
                    self.lifecycle_backstop();
                }
                Some(req) = gossip_rx.recv() => {
                    let GossipPublish { topic, data, respond_to } = req;
                    let data_len = data.len() as u64;
                    let topic_obj = libp2p::gossipsub::IdentTopic::new(&topic);
                    let outcome = match self.swarm.behaviour_mut().gossipsub.publish(topic_obj, data) {
                        Ok(_) => {
                            self.counters.add_bytes_out(data_len);
                            self.counters.inc_messages_relayed();
                            debug!(topic = %topic, "Published message to GossipSub");
                            PublishOutcome::Propagated
                        }
                        Err(e) => {
                            self.report_publish_failure(&topic, &e);
                            PublishOutcome::Degraded
                        }
                    };
                    // Best-effort: the caller may have timed out and
                    // dropped the receiver — a send error is expected
                    // and ignorable. `None` respond_to means a
                    // fire-and-forget internal re-publish.
                    if let Some(tx) = respond_to {
                        let _ = tx.send(outcome);
                    }
                }
                _ = mesh_stats_interval.tick() => {
                    self.refresh_mesh_stats();
                    // W10: piggyback the gossip rate-limiter/app-score sweep
                    // on this existing 30s tick rather than adding a
                    // dedicated interval — bounds `gossip_rate_limiter` /
                    // `gossip_app_score` memory under peer churn.
                    self.prune_gossip_rate_state();
                }
                _ = presence_interval.tick() => {
                    // Steady-state rebroadcast — don't care about
                    // success here; the next tick fires regardless.
                    let _ = self.publish_presence_self_record();
                }
                _ = dm_reap_interval.tick() => {
                    self.reap_expired_dms();
                }
                _ = async {
                    match identity_staleness_interval.as_mut() {
                        Some(iv) => { iv.tick().await; }
                        None => std::future::pending().await,
                    }
                } => {
                    self.sweep_identity_staleness();
                }
                _ = announce_interval.tick() => {
                    self.publish_node_announcement();
                }
                _ = hot_topics_interval.tick() => {
                    self.publish_hot_topics_digest();
                    self.hot_topics.prune_rate_limiter();
                }
                _ = bootstrap_interval.tick() => {
                    self.periodic_bootstrap();
                    // P-3: global-news reconciliation. Runs once peers exist,
                    // then repeats on `news_catchup_interval_hours` so a post
                    // missed while this node was down or unmeshed is recovered
                    // rather than lost permanently.
                    self.maybe_trigger_news_backfill();
                    // l2-node 0.136.0: same idea, per channel — see
                    // `retry_incomplete_channel_backfills`'s doc comment.
                    self.retry_incomplete_channel_backfills();
                    // l2-node 0.138.0: same idea again, for private-channel
                    // history (F2 backfill gap) — see
                    // `retry_incomplete_private_channel_syncs`'s doc comment.
                    self.retry_incomplete_private_channel_syncs();
                    // l2-node 0.150.0 (Phase E): the same for local
                    // members recorded only in LOCAL_CHANNEL_HOMES.
                    self.retry_incomplete_private_channel_syncs_homes();
                    // l2-node 0.141.0: drop refilled responder-budget
                    // entries (never one in debt) and long-idle throttle
                    // entries.
                    self.prune_backfill_budgets(Instant::now());
                }
                _ = reconnect_interval.tick() => {
                    self.process_reconnect_queue();
                }
                _ = reconcile_compare_interval.tick() => {
                    self.finalize_expired_reconcile_comparisons();
                }
                Some(_) = sc_reconnect_rx.recv() => {
                    // sc_discovery persisted new multiaddrs from the
                    // on-chain registry — dial them now. dial_persisted_peers
                    // skips peers that are already connected or being
                    // dialed (`PeerCondition::DisconnectedAndNotDialing`).
                    debug!("sc_discovery signaled new peers; dialing from book out-of-cycle");
                    self.dial_persisted_peers();
                }
                Some(cmd) = self.snapshot_client_rx.recv() => {
                    self.handle_snapshot_client_command(cmd);
                }
                Some(deferred) = async {
                    match deferred_response_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.send_deferred_response(deferred);
                }
                Some(outcome) = async {
                    match presence_validation_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        // Disabled-presence path: park forever so this
                        // branch is never selected. `None` from
                        // `rx.recv()` would terminate the loop unfairly.
                        None => std::future::pending().await,
                    }
                } => {
                    // Spec 13 §10.3: report the validation result back
                    // to gossipsub so it forwards (Accept) or suppresses
                    // (Reject/Ignore) the message across the mesh.
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .report_message_validation_result(
                            &outcome.message_id,
                            &outcome.propagation_source,
                            outcome.acceptance,
                        );
                }
                _ = shutdown_rx.recv() => {
                    info!("Network shutting down");
                    break;
                }
            }
        }
    }

    /// Pick the node-wide build slot for an inbound backfill request
    /// (round-5 C-W1): a free build slot → `Now`; none free → `Wait` for a
    /// continuation request (`continuation`: it carries a cursor) while a
    /// waiter slot is free, else `Refuse`.
    fn responder_build_slot(&self, continuation: bool) -> BuildSlot {
        pick_build_slot(&self.responder_build_permits, &self.continuation_wait_permits, continuation)
    }

    /// Send a backfill response that was built off the event loop
    /// (`DeferredResponse`). The responder guard and the build slot are
    /// dropped (end of this function) after the response is handed to
    /// libp2p, as when the build ran inline.
    fn send_deferred_response(&mut self, deferred: DeferredResponse) {
        match deferred {
            DeferredResponse::PrivateChannelSync { peer, channel, response, .. } => {
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .private_channel_sync
                    .send_response(channel, response)
                {
                    warn!(peer = %peer, error = ?e, "private-channel-sync: send_response failed");
                }
            }
            DeferredResponse::Reconcile { peer, channel_id, channel, response, .. } => {
                let envelopes_sent = response.envelopes.len();
                let has_more = response.has_more;
                if let Err(e) = self.swarm.behaviour_mut().reconcile.send_response(channel, response) {
                    warn!(peer = %peer, channel_id, error = ?e, "reconcile: send_response failed");
                }
                debug!(peer = %peer, channel_id, envelopes_sent, has_more, "reconcile: served request");
            }
        }
    }

    /// Handle a single swarm event.
    fn handle_swarm_event(&mut self, event: SwarmEvent<OgmaraBehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::Message {
                    propagation_source,
                    message_id,
                    message,
                },
            )) => {
                debug!(
                    source = %propagation_source,
                    msg_id = %message_id,
                    topic = %message.topic,
                    bytes = message.data.len(),
                    "Received GossipSub message"
                );
                // Spec 13 §10.3: presence-topic messages take a
                // separate validation path. Other topics fall through
                // to the standard envelope router.
                let on_presence_topic = self
                    .presence_topic_hash
                    .as_ref()
                    .map(|h| *h == message.topic)
                    .unwrap_or(false);
                let on_network_topic = message.topic == self.network_topic_hash;
                if on_presence_topic {
                    // The presence handler reports validation outcome
                    // back through `presence_validation_tx` once the
                    // async verifier finishes — DO NOT report here.
                    self.handle_presence_message(
                        propagation_source,
                        message_id,
                        message.data,
                    );
                } else if !self.check_gossip_rate_limit(propagation_source) {
                    // Audit final pre-mainnet W10: per-peer rate limit,
                    // checked BEFORE any per-message work (the envelope router
                    // OR the Hot Topics digest path — Security Audit W1) so a
                    // flooding peer's messages are dropped without paying the
                    // decode/verify/storage cost. `Ignore`, not `Reject`.
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            libp2p::gossipsub::MessageAcceptance::Ignore,
                        );
                } else {
                    // Hot Topics digest (0xE1, spec 3 §3.9) on the /network
                    // topic: cheap validation runs here, the RocksDB fold is
                    // done off the swarm loop (Code+Security Audit W1).
                    // `NotADigest` (e.g. a NodeAnnouncement) falls through to
                    // the generic envelope router.
                    let mut handled = false;
                    if on_network_topic {
                        let acc = match self.hot_topics.classify_and_validate(
                            propagation_source,
                            &message.data,
                            hot_topics::now_ms(),
                        ) {
                            hot_topics::InboundDecision::NotADigest => None,
                            hot_topics::InboundDecision::Fold(vd) => {
                                self.adjust_gossip_app_score(
                                    propagation_source,
                                    VALID_MESSAGE_SCORE_RECOVERY,
                                );
                                let agg = self.hot_topics.clone();
                                tokio::task::spawn_blocking(move || agg.fold(*vd));
                                Some(libp2p::gossipsub::MessageAcceptance::Accept)
                            }
                            hot_topics::InboundDecision::Reject(reason) => {
                                debug!(reason = %reason, "hot-topics digest invalid — rejecting");
                                self.counters.inc_failed_validations();
                                self.adjust_gossip_app_score(
                                    propagation_source,
                                    -INVALID_MESSAGE_SCORE_PENALTY,
                                );
                                Some(libp2p::gossipsub::MessageAcceptance::Reject)
                            }
                            hot_topics::InboundDecision::Ignore(reason) => {
                                debug!(reason = %reason, "hot-topics digest not folded — ignoring");
                                Some(libp2p::gossipsub::MessageAcceptance::Ignore)
                            }
                        };
                        if let Some(acc) = acc {
                            let _ = self
                                .swarm
                                .behaviour_mut()
                                .gossipsub
                                .report_message_validation_result(
                                    &message_id,
                                    &propagation_source,
                                    acc,
                                );
                            handled = true;
                        }
                    }
                    if !handled {
                        // Spec 13 §10.3 + v0.48.0: gossipsub is configured with
                        // `.validate_messages()`, so EVERY received message must
                        // produce a validation result or relay stalls.
                        let acceptance =
                            self.handle_gossip_message(propagation_source, &message.data);
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .gossipsub
                            .report_message_validation_result(
                                &message_id,
                                &propagation_source,
                                acceptance,
                            );
                    }
                }
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::Subscribed { peer_id, topic },
            )) => {
                debug!(peer = %peer_id, topic = %topic, "Peer subscribed to topic");
                // v0.48.3: retry the presence initial-broadcast when a
                // remote peer subscribes to our presence topic. The
                // ConnectionEstablished trigger fires too early —
                // gossipsub hasn't yet exchanged subscription RPCs, so
                // the publish fails with `NoPeersSubscribedToTopic`
                // even though the libp2p connection is up. The
                // Subscribed event is the right moment: at that point
                // we KNOW there's at least one peer in the topic mesh.
                let is_presence_topic = self
                    .presence_topic_hash
                    .as_ref()
                    .map(|h| h == &topic)
                    .unwrap_or(false);
                if is_presence_topic {
                    self.maybe_publish_initial_presence();
                }
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::Unsubscribed { peer_id, topic },
            )) => {
                debug!(peer = %peer_id, topic = %topic, "Peer unsubscribed from topic");
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::GossipsubNotSupported { peer_id },
            )) => {
                info!(peer = %peer_id, "Peer does not support GossipSub");
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Mdns(
                libp2p::mdns::Event::Discovered(peers),
            )) => {
                for (peer_id, addr) in peers {
                    debug!(peer = %peer_id, addr = %addr, "mDNS discovered peer");
                    // Only dial the peer — do NOT add to Kademlia or GossipSub yet.
                    // The Identify handler will promote same-network peers after
                    // verifying the protocol version. This prevents wrong-network
                    // peers (e.g., testnet+mainnet on the same LAN) from polluting
                    // the routing table or receiving GossipSub messages.
                    if let Err(e) = self.swarm.dial(addr) {
                        debug!(peer = %peer_id, error = %e, "Failed to dial mDNS peer");
                    }
                }
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Mdns(
                libp2p::mdns::Event::Expired(peers),
            )) => {
                for (peer_id, _addr) in peers {
                    debug!(peer = %peer_id, "mDNS peer expired");
                }
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Kademlia(event)) => {
                match &event {
                    kad::Event::RoutingUpdated {
                        peer, addresses, ..
                    } => {
                        info!(
                            peer = %peer,
                            addresses = addresses.len(),
                            "Kademlia routing table updated"
                        );
                    }
                    kad::Event::OutboundQueryProgressed { result, .. } => {
                        debug!(result = ?result, "Kademlia query progressed");
                    }
                    _ => {
                        debug!(event = ?event, "Kademlia event");
                    }
                }
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Identify(
                libp2p::identify::Event::Received { peer_id, info, .. },
            )) => {
                // Network isolation: only accept peers on the same network.
                // Protocol version format: /ogmara/{network_id}/1.0.0
                let expected_prefix = format!("/ogmara/{}/", self.topics.network_id());
                let is_ogmara = info.protocol_version.starts_with(&expected_prefix);
                let agent_ver = info.agent_version.clone();

                // Reject peers that are not on our network — disconnect immediately.
                if !is_ogmara {
                    if info.protocol_version.starts_with("/ogmara/") {
                        warn!(
                            peer = %peer_id,
                            their_protocol = %info.protocol_version,
                            our_network = %self.topics.network_id(),
                            "Rejecting peer from different network — disconnecting"
                        );
                    } else {
                        debug!(
                            peer = %peer_id,
                            protocol_version = %info.protocol_version,
                            "Non-Ogmara peer identified — disconnecting"
                        );
                    }
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                }

                info!(
                    peer = %peer_id,
                    protocol_version = %info.protocol_version,
                    agent_version = %agent_ver,
                    listen_addrs = info.listen_addrs.len(),
                    "Identified Ogmara peer"
                );
                // Spec 13 §4.3 stall-trigger signal: every successful
                // Ogmara Identify bumps this counter, which sc_discovery
                // reads at +60s post-startup. Zero ⇒ we are isolated
                // (tier 1 + 2 produced nothing) ⇒ fire SC fan-out.
                self.identify_success_count.fetch_add(1, Ordering::Relaxed);

                // Add identified peer's ROUTABLE addresses to Kademlia and
                // store the first for reconnection. A node listening on
                // `0.0.0.0` reports every local interface via Identify
                // (127.0.0.1, docker bridge, RFC1918 LAN, CGNAT/tailscale).
                // Ingesting those unfiltered (audit follow-up 2026-06-08) made
                // peers dial private addresses → `WrongPeerId` / dialing
                // themselves (`LocalPeerId`), and clobbered the on-chain
                // `/dns4` addr in PEER_DIRECTORY — which broke the gossip mesh
                // + `NodeAnnouncement` propagation. Filter through the same
                // `classify_transport` guard the SC-discovery path already uses
                // (audit C2): keep only Clearnet/Onion/I2p, drop `Unknown`
                // (loopback / private / CGNAT / link-local).
                // The address kept for reconnection uses the same ranking
                // as SC discovery (clearnet before onion/i2p): Identify's
                // address order is arbitrary (a HashSet upstream), and an
                // onion address stored here would be undialable for nodes
                // without Tor and eventually evict the peer.
                let mut first_addr: Option<(u8, Multiaddr)> = None;
                for addr in info.listen_addrs.into_iter().take(16) {
                    let Some(rank) = sc_discovery::persist_rank(&addr) else {
                        continue; // non-routable — never dial or persist it
                    };
                    if first_addr.as_ref().is_none_or(|(best, _)| rank < *best) {
                        first_addr = Some((rank, addr.clone()));
                    }
                    self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                }
                let first_addr = first_addr.map(|(_, addr)| addr);
                // Store address for reconnection (capped to prevent unbounded growth)
                if let Some(ref addr) = first_addr {
                    if self.known_peer_addrs.len() < 2048 || self.known_peer_addrs.contains_key(&peer_id) {
                        self.known_peer_addrs.insert(peer_id, addr.clone());
                    }
                }
                // Persist peer address to storage for reconnection after restart.
                if let Some(ref addr) = first_addr {
                    self.persist_peer_addr(&peer_id, addr);
                }
                // Remove from reconnect queue if it was pending (successfully connected)
                self.reconnect_queue.retain(|e| e.peer_id != peer_id);

                // Sync channel messages from this peer
                self.sync_channels_with_peer(peer_id);

                // Track this peer so it appears in /api/v1/network/nodes
                // even before its NodeAnnouncement arrives via GossipSub
                if let Ok(ed25519_pk) = info.public_key.try_into_ed25519() {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(ed25519_pk.to_bytes());
                    let node_id = bs58::encode(&hash[..20]).into_string();
                    self.peer_node_ids.insert(peer_id, node_id.clone());
                    // NOTE (l2-node 0.66.0): verified Ogmara peers are
                    // deliberately NOT marked as gossipsub EXPLICIT peers.
                    // An earlier build (2026-06-08) did so to work around an
                    // empty mesh — but gossipsub *excludes* explicit peers from
                    // mesh grafting (`get_random_peers`'s filter requires
                    // `!explicit_peers.contains(peer)`). On the small fleet,
                    // where every peer was marked explicit, the mesh could
                    // therefore NEVER form: peers grafted on subscribe, then
                    // `add_explicit_peer` evicted them, leaving `mesh_size = 0`
                    // permanently ("RANDOM PEERS: Got 0 peers"). That forced all
                    // cross-node traffic onto the explicit-peer DIRECT-FORWARD
                    // path, which carries no IHAVE/IWANT recovery — so any drop
                    // (reconnect window, inbound-only link) was permanent,
                    // producing the intermittent cross-node DM loss and
                    // "waiting for key" symptoms. The original empty-mesh cause
                    // (`mesh_outbound_min = 1` blocking inbound-only nodes) was
                    // since fixed properly via `mesh_outbound_min = 0` (see
                    // behaviour.rs), so peers now graft into a real, stable mesh
                    // (mesh_n=3, never exceeds mesh_n_high) and regain
                    // gossip-based recovery. Peer identity is still tracked
                    // below for `/api/v1/network/nodes` + telemetry.
                    // Spec 13 §4.1 — classify which bootstrap tier
                    // produced this peer's dial chain this session.
                    let source = self.classify_discovery_source(&peer_id);
                    // Note: do not hold this lock across .await points
                    match self.connected_peers.write() {
                        Ok(mut peers) => {
                            // Defensive cap to prevent unbounded growth
                            if peers.len() < 1024 || peers.contains_key(&node_id) {
                                peers.insert(node_id, ConnectedPeerInfo {
                                    // Security Audit follow-up (W17, l2-node
                                    // 0.102.0): `agent_ver` is raw,
                                    // unauthenticated peer-supplied data from
                                    // libp2p Identify — every fresh
                                    // connection sends one, no PoW/auth
                                    // gates it. A byte-range index
                                    // (`agent_ver[..256]`) panics if 256
                                    // doesn't land on a UTF-8 char boundary,
                                    // trivially triggerable (255 ASCII bytes
                                    // + one multi-byte codepoint). Before
                                    // W17 this only killed the network task;
                                    // W17's fail-fast design means the same
                                    // panic now kills the whole process —
                                    // this was a pre-existing bug whose
                                    // blast radius W17 materially widened,
                                    // so it's fixed alongside it.
                                    // `truncate_str` (util.rs) is the
                                    // existing char-boundary-safe pattern,
                                    // already used elsewhere (chain/scanner.rs).
                                    agent_version: crate::util::truncate_str(&agent_ver, 256).to_string(),
                                    source,
                                    peer_id: peer_id.to_base58(),
                                });
                            }
                        }
                        Err(e) => warn!("connected_peers lock poisoned: {e}"),
                    }
                }
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::RequestResponse(event)) => {
                self.handle_request_response(event);
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Snapshot(event)) => {
                self.handle_snapshot_event(event);
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Reconcile(event)) => {
                self.handle_reconcile_event(event);
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::IdentitySync(event)) => {
                self.handle_identity_sync_event(event);
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::NewsSync(event)) => {
                self.handle_news_sync_event(event);
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::DmSync(event)) => {
                self.handle_dm_sync_event(event);
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::PrivateChannelSync(event)) => {
                self.handle_private_channel_sync_event(event);
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                info!(addr = %address, "Listening on new address");
            }

            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                endpoint,
                ..
            } => {
                let total_peers = self.swarm.connected_peers().count();
                self.peer_count.store(total_peers as u32, Ordering::Relaxed);
                // B4 peer-telemetry (0.48.4): track this connection's
                // direction so `/admin/network/peer-telemetry` can show
                // the inbound/outbound balance that diagnoses asymmetric
                // meshes. `is_dialer()` ⇒ we dialed ⇒ outbound.
                {
                    let entry = self.peer_directions.entry(peer_id).or_insert((0, 0));
                    if endpoint.is_dialer() {
                        entry.0 = entry.0.saturating_add(1);
                    } else {
                        entry.1 = entry.1.saturating_add(1);
                    }
                }
                info!(
                    peer = %peer_id,
                    connections = %num_established,
                    total_peers,
                    direction = if endpoint.is_dialer() { "outbound" } else { "inbound" },
                    remote_addr = %endpoint.get_remote_address(),
                    "Connection established"
                );
                // Trigger Kademlia bootstrap when we get our first peer
                if total_peers == 1 {
                    if let Err(e) = self.swarm.behaviour_mut().kademlia.bootstrap() {
                        debug!(error = %e, "Kademlia bootstrap not ready yet");
                    }
                    // Announce ourselves immediately so other nodes know we exist
                    self.publish_node_announcement();
                }
                // Spec 13 §10.5: one-shot presence broadcast on mesh
                // stabilization (≥ 3 peers, first time this process).
                self.maybe_publish_initial_presence();
            }

            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                cause,
                endpoint,
                ..
            } => {
                let total_peers = self.swarm.connected_peers().count();
                self.peer_count.store(total_peers as u32, Ordering::Relaxed);
                // B4 peer-telemetry (0.48.4): decrement the matching
                // direction counter for the connection that closed.
                // `num_established == 0` means this was the peer's last
                // connection, so drop the entry entirely to bound the
                // map; otherwise saturating-decrement the one direction.
                if num_established == 0 {
                    self.peer_directions.remove(&peer_id);
                } else if let Some(entry) = self.peer_directions.get_mut(&peer_id) {
                    if endpoint.is_dialer() {
                        entry.0 = entry.0.saturating_sub(1);
                    } else {
                        entry.1 = entry.1.saturating_sub(1);
                    }
                }
                if let Some(ref err) = cause {
                    warn!(
                        peer = %peer_id,
                        remaining = %num_established,
                        total_peers,
                        cause = %err,
                        "Connection closed with error"
                    );
                } else {
                    info!(
                        peer = %peer_id,
                        remaining = %num_established,
                        total_peers,
                        "Connection closed"
                    );
                }
                // Remove from connected peers when last connection to this peer closes
                if num_established == 0 {
                    if let Some(node_id) = self.peer_node_ids.remove(&peer_id) {
                        match self.connected_peers.write() {
                            Ok(mut peers) => { peers.remove(&node_id); }
                            Err(e) => warn!("connected_peers lock poisoned: {e}"),
                        }
                    }
                    // Queue for reconnection with exponential backoff
                    self.queue_reconnect(peer_id);
                }
            }

            SwarmEvent::OutgoingConnectionError {
                peer_id,
                error,
                ..
            } => {
                warn!(
                    peer = ?peer_id,
                    error = %error,
                    "Outgoing connection failed"
                );
            }

            SwarmEvent::IncomingConnectionError {
                local_addr,
                send_back_addr,
                error,
                ..
            } => {
                warn!(
                    local_addr = %local_addr,
                    remote_addr = %send_back_addr,
                    error = %error,
                    "Incoming connection failed"
                );
            }

            SwarmEvent::Dialing { peer_id, .. } => {
                debug!(peer = ?peer_id, "Dialing peer");
            }

            _ => {}
        }
    }

    /// Key prefix for persisted peer addresses in PEER_DIRECTORY CF.
    /// Separates peer addrs from NodeAnnouncement entries which use no prefix.
    const PEER_ADDR_PREFIX: &'static [u8] = b"pa:";

    /// Persist a peer's multiaddr to storage for reconnection after restart.
    fn persist_peer_addr(&self, peer_id: &PeerId, addr: &Multiaddr) {
        // Defense-in-depth (audit follow-up 2026-06-08): never persist a
        // non-routable addr. PEER_DIRECTORY's `pa:` keyspace is shared with the
        // SC-discovery path, so a private/loopback Identify addr here would
        // both be dialed on restart AND clobber the routable on-chain `/dns4`
        // entry. The Identify call site already filters, but guard here too.
        if crate::chain::sc_views::classify_transport(&addr.to_string())
            == crate::chain::sc_views::TransportKind::Unknown
        {
            return;
        }
        // Cap stored peers at 256 to prevent unbounded growth
        let existing = self.storage.prefix_iter_cf(
            crate::storage::schema::cf::PEER_DIRECTORY,
            Self::PEER_ADDR_PREFIX,
            257,
        ).map(|e| e.len()).unwrap_or(0);
        if existing >= 256 {
            return; // full — existing peers are retained, new ones skipped
        }

        let mut key = Vec::with_capacity(3 + 64);
        key.extend_from_slice(Self::PEER_ADDR_PREFIX);
        key.extend_from_slice(peer_id.to_string().as_bytes());
        let value = addr.to_string();
        if let Err(e) = self.storage.put_cf(
            crate::storage::schema::cf::PEER_DIRECTORY,
            &key,
            value.as_bytes(),
        ) {
            warn!(error = %e, "Failed to persist peer address");
        }
    }

    /// Remove a peer's stored address (e.g., after giving up on reconnection).
    fn remove_persisted_peer(&self, peer_id: &PeerId) {
        let mut key = Vec::with_capacity(3 + 64);
        key.extend_from_slice(Self::PEER_ADDR_PREFIX);
        key.extend_from_slice(peer_id.to_string().as_bytes());
        if let Err(e) = self.storage.delete_cf(
            crate::storage::schema::cf::PEER_DIRECTORY,
            &key,
        ) {
            debug!(error = %e, "Failed to remove persisted peer");
        }
    }

    /// Load persisted peer addresses from storage and dial them.
    ///
    /// Called once at startup to reconnect to previously-known peers
    /// without relying on bootstrap nodes.
    fn dial_persisted_peers(&mut self) {
        let entries = match self.storage.prefix_iter_cf(
            crate::storage::schema::cf::PEER_DIRECTORY,
            Self::PEER_ADDR_PREFIX,
            64, // cap to prevent dialing too many at once
        ) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "Failed to load persisted peers");
                return;
            }
        };

        if entries.is_empty() {
            return;
        }

        let mut dialed = 0u32;
        for (key, value) in &entries {
            let addr_str = match std::str::from_utf8(value) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let addr: Multiaddr = match addr_str.parse() {
                Ok(a) => a,
                Err(_) => continue,
            };

            // A bare `dial(Multiaddr)` uses `PeerCondition::Always`, so it
            // would redial peers we are already connected to — for onion
            // peers that is a fresh Tor circuit refused only after Noise.
            // With a known peer id, skip connected or in-flight peers.
            // The row key is `pa:<peer_id>`; Identify-written rows carry no
            // `/p2p` segment, so take the id from the key first.
            let peer_id = key
                .strip_prefix(Self::PEER_ADDR_PREFIX)
                .and_then(|k| std::str::from_utf8(k).ok())
                .and_then(|k| k.parse::<PeerId>().ok())
                .or_else(|| {
                    addr.iter().find_map(|p| match p {
                        libp2p::multiaddr::Protocol::P2p(id) => Some(id),
                        _ => None,
                    })
                });
            let opts = match peer_id {
                Some(id) => libp2p::swarm::dial_opts::DialOpts::peer_id(id)
                    .addresses(vec![addr.clone()])
                    .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
                    .build(),
                None => addr.clone().into(),
            };
            match self.swarm.dial(opts) {
                Ok(()) => dialed += 1,
                Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {}
                Err(e) => debug!(addr = %addr, error = %e, "Failed to dial persisted peer"),
            }
        }

        if dialed > 0 {
            info!(dialed, stored = entries.len(), "Dialing persisted peers from previous session");
        }
    }

    /// Periodic bootstrap: if peers are low, redial bootstrap nodes and run Kademlia bootstrap.
    ///
    /// Fixes the deadlock where Kademlia bootstrap was skipped when peer_count==0,
    /// preventing peer discovery from ever starting.
    fn periodic_bootstrap(&mut self) {
        let peer_count = self.swarm.connected_peers().count();

        if peer_count == 0 {
            // No peers at all — actively redial bootstrap nodes
            info!("No connected peers — redialing bootstrap nodes");
            for addr in self.bootstrap_addrs.clone() {
                // Check if we're already connected to this peer
                let peer_id = addr.iter().find_map(|proto| {
                    if let libp2p::multiaddr::Protocol::P2p(id) = proto {
                        Some(id)
                    } else {
                        None
                    }
                });
                let already_connected = peer_id
                    .map(|pid| self.swarm.is_connected(&pid))
                    .unwrap_or(false);

                if !already_connected {
                    if let Err(e) = self.swarm.dial(addr.clone()) {
                        warn!(addr = %addr, error = %e, "Bootstrap redial failed");
                    } else {
                        info!(addr = %addr, "Redialing bootstrap node");
                    }
                }
            }
        }

        // Always attempt Kademlia bootstrap regardless of peer count.
        // With 0 peers, Kademlia will use its routing table (which may
        // have bootstrap node entries even without active connections).
        match self.swarm.behaviour_mut().kademlia.bootstrap() {
            Ok(_) => debug!(peer_count, "Kademlia bootstrap triggered"),
            Err(e) => debug!(error = %e, "Kademlia bootstrap skipped (no known peers in routing table)"),
        }
    }

    /// Report a GossipSub publish failure: classify the error variant,
    /// bump the appropriate counter, emit a per-failure `error!` log
    /// with the data that step 2 of the mainnet-blockers fix plan
    /// (B4 instrumentation) requires for diagnosis — peer count +
    /// per-topic subscriber count, both at the moment of failure —
    /// and fire `publish_failed_insufficient_peers` (cooldown-
    /// deduplicated by AlertEngine) when the variant is
    /// `NoPeersSubscribedToTopic`.
    ///
    /// Logging is `error!` not `warn!` because a silent publish failure
    /// is the hardest possible class of bug to diagnose post-hoc
    /// (messages just disappear). `warn!` previously buried this in
    /// the noise floor of "transient peer churn" — `error!` plus
    /// structured fields plus the new counters make the asymmetric-
    /// propagation case the plan calls out actually observable.
    fn report_publish_failure(
        &self,
        topic: &str,
        err: &libp2p::gossipsub::PublishError,
    ) {
        let fire_insufficient_peers_alert =
            self.publish_failure_counters.record(err);

        let connected_peers = self.swarm.connected_peers().count();
        let topic_hash = libp2p::gossipsub::IdentTopic::new(topic).hash();
        let topic_subscribers = self
            .swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .filter(|(_, topics)| topics.iter().any(|t| **t == topic_hash))
            .count();
        let mesh_size = self
            .swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&topic_hash)
            .count();

        error!(
            topic = %topic,
            error = %err,
            connected_peers,
            topic_subscribers,
            mesh_size,
            "GossipSub publish failed"
        );

        if fire_insufficient_peers_alert {
            self.fire_publish_failed_alert(topic, connected_peers, topic_subscribers);
        }
    }

    /// Fire the `publish_failed_insufficient_peers` alert with the
    /// snapshot of state that diagnosis needs.
    ///
    /// **Topic redaction (Security Audit W1, 0.46.6).** The raw topic
    /// strings produced by `gossip::dm_topic` and `gossip::channel_topic`
    /// include the recipient wallet (`/ogmara/<network>/v1/dm/klv1...`)
    /// or channel ID. AlertEngine dispatches this `details` field to
    /// Telegram / Discord / webhook sinks — putting the plaintext
    /// topic in the payload would leak DM-recipient and channel
    /// metadata to whichever third-party messaging service the
    /// operator pointed alerts at. We render the topic as its
    /// `IdentTopic::hash()` (the same SHA-256-shaped rendering the
    /// `/admin/network/mesh-stats` snapshot uses) so the alert
    /// payload is correlateable with the local snapshot but does not
    /// expose plaintext topics to outbound dispatchers.
    ///
    /// Best-effort (`try_send`) — channel-full means the AlertEngine
    /// is stalled (capacity 1024), so dropping is correct; the engine
    /// either recovers and picks up the next event, or the operator
    /// has a separate observability problem.
    fn fire_publish_failed_alert(
        &self,
        topic: &str,
        connected_peers: usize,
        topic_subscribers: usize,
    ) {
        let Some(tx) = self.alert_event_tx.as_ref() else {
            return;
        };
        let topic_render =
            libp2p::gossipsub::IdentTopic::new(topic).hash().to_string();
        let event = crate::notifications::alerts::AlertEvent {
            alert_type:
                crate::notifications::alerts::AlertType::PublishFailedInsufficientPeers,
            details: format!(
                "publish failed: no peers subscribed (topic_hash={topic_render}, \
                 connected_peers={connected_peers}, \
                 topic_subscribers={topic_subscribers})"
            ),
        };
        if let Err(e) = tx.try_send(event) {
            debug!(error = %e, "publish-failed alert channel full or closed");
        }
    }

    /// Refresh the shared `MeshStatsSnapshot` from the current state of
    /// `gossipsub::Behaviour`. Called from the main loop on the 30s
    /// `mesh_stats_interval` tick. Lock-hold is sub-millisecond — we
    /// build the snapshot in a local, then swap it in under the
    /// `RwLock` write guard.
    fn refresh_mesh_stats(&self) {
        use std::collections::HashMap;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let gossipsub = &self.swarm.behaviour().gossipsub;

        // Walk every subscribed topic. `topics()` returns the topic
        // hashes we are subscribed to — we don't have the original
        // topic-string here without a side-table, so the snapshot
        // surfaces the hash rendering (operators recognise the
        // network_id / topic prefix in the rendering).
        let mut topic_entries: HashMap<String, mesh_stats::TopicMeshStats> = HashMap::new();
        let mut total_mesh_slots = 0usize;
        // Per-peer count of how many topic meshes each peer shares with
        // us — joined with the direction map below for the peer-
        // telemetry view.
        let mut mesh_topic_count: HashMap<PeerId, usize> = HashMap::new();
        for topic_hash in gossipsub.topics() {
            let mesh_size = gossipsub.mesh_peers(topic_hash).count();
            total_mesh_slots += mesh_size;
            for mesh_peer in gossipsub.mesh_peers(topic_hash) {
                *mesh_topic_count.entry(*mesh_peer).or_insert(0) += 1;
            }
            let subscribers = gossipsub
                .all_peers()
                .filter(|(_, topics)| topics.iter().any(|t| *t == topic_hash))
                .count();
            if mesh_size == 0 && subscribers == 0 {
                continue;
            }
            let topic_str = topic_hash.to_string();
            topic_entries.insert(
                topic_str.clone(),
                mesh_stats::TopicMeshStats {
                    topic: topic_str,
                    mesh_size,
                    subscribers,
                },
            );
        }

        let mut topics: Vec<mesh_stats::TopicMeshStats> =
            topic_entries.into_values().collect();
        topics.sort_by(|a, b| a.topic.cmp(&b.topic));

        let (total, no_peers, all_queues_full, other) =
            self.publish_failure_counters.snapshot();

        // B4 peer-telemetry: project the direction map into per-peer
        // rows plus the inbound/outbound aggregates. `outbound_peers`
        // counts peers reachable via ≥1 dialed connection;
        // `inbound_only_peers` is the B4 risk signal.
        let mut peers: Vec<mesh_stats::PeerConnStats> = self
            .peer_directions
            .iter()
            .map(|(peer_id, (outbound, inbound))| mesh_stats::PeerConnStats {
                peer_id: peer_id.to_string(),
                outbound_conns: *outbound,
                inbound_conns: *inbound,
                mesh_topics: mesh_topic_count.get(peer_id).copied().unwrap_or(0),
            })
            .collect();
        peers.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        // `total_peers` here is "peers with tracked direction state"
        // (from `peer_directions`) — distinct from the live
        // `self.peer_count` (swarm `connected_peers().count()`). Both
        // are driven by the same connection events so they agree in
        // steady state, but may differ momentarily between the 30s
        // refresh tick and an interleaved connection event.
        let total_peers = peers.len();
        let outbound_peers = peers.iter().filter(|p| p.outbound_conns > 0).count();
        let inbound_only_peers = peers
            .iter()
            .filter(|p| p.outbound_conns == 0 && p.inbound_conns > 0)
            .count();

        let new_snapshot = mesh_stats::MeshStatsSnapshot {
            generated_at_unix: now_unix,
            topics,
            total_mesh_slots,
            publish_failures_total: total,
            publish_failures_no_peers: no_peers,
            publish_failures_all_queues_full: all_queues_full,
            publish_failures_other: other,
            total_peers,
            outbound_peers,
            inbound_only_peers,
            peers,
        };

        match self.mesh_stats.write() {
            Ok(mut w) => *w = new_snapshot,
            Err(e) => warn!(error = %e, "mesh_stats RwLock poisoned"),
        }
    }

    /// Bound on `identity_sync_triggered`'s size before the oldest entry is
    /// evicted (see `identity_sync_triggered_insert`).
    const MAX_IDENTITY_SYNC_TRIGGERED: usize = 100_000;

    /// Insert into the bounded `identity_sync_triggered` dedup set, evicting
    /// the single oldest entry when at capacity (mirrors
    /// `IdentityResponderLimits::add_served`'s oldest-eviction pattern). A
    /// no-op if `wallet` is already present.
    fn identity_sync_triggered_insert(&mut self, wallet: String) {
        if !self.identity_sync_triggered.insert(wallet.clone()) {
            return; // already present — order queue already has it
        }
        self.identity_sync_triggered_order.push_back(wallet);
        if self.identity_sync_triggered.len() > Self::MAX_IDENTITY_SYNC_TRIGGERED {
            if let Some(oldest) = self.identity_sync_triggered_order.pop_front() {
                self.identity_sync_triggered.remove(&oldest);
            }
        }
    }

    /// Remove `wallet` from the bounded `identity_sync_triggered` dedup set
    /// (both the set and its order queue), allowing a future re-trigger.
    /// `VecDeque` has no O(1) remove-by-value, so this is O(n) in the
    /// order queue's length — acceptable because every caller is
    /// low-frequency (the sweep's `≤max_retriggers_per_sweep` per tick, the
    /// pending-cap rollback, the no-connected-peers rollback), never the
    /// per-message gossip hot path.
    fn identity_sync_triggered_remove(&mut self, wallet: &str) {
        if self.identity_sync_triggered.remove(wallet) {
            self.identity_sync_triggered_order.retain(|w| w != wallet);
        }
    }

    /// The observed-author identity-pull gate (design doc "Closing the
    /// Identity-Sync Coverage Gap"), shared by live gossip and — since
    /// l2-node 0.151.0 (G9) — the authors of `Accepted` envelopes from
    /// channel reconcile and news-sync. Fires a `SCOPE_ALL` pull only when
    /// ALL hold, cheapest first: the feature is enabled; the per-interval
    /// `observed_trigger_budget` is not spent; the wallet was not already
    /// pulled this session; the message type is author-facing
    /// (`triggers_identity_check`); and the local identity record looks
    /// incomplete (`identity_looks_incomplete`, one `USERS` read). `backfill`
    /// selects the budget: `backfill_author_trigger_budget` for authors of
    /// synced envelopes, `observed_trigger_budget` for live gossip. Returns
    /// whether a pull was triggered. See `handle_gossip_message` for the
    /// threat model behind each condition.
    fn observe_author_for_identity_pull(&mut self, author: &str, msg_type: u8, backfill: bool) -> bool {
        let budget = if backfill { self.backfill_author_trigger_budget } else { self.observed_trigger_budget };
        if !(self.identity_resync_config.enabled
            && budget > 0
            && !self.identity_sync_triggered.contains(author)
            && identity_sync::triggers_identity_check(msg_type)
            && identity_sync::identity_looks_incomplete(&self.storage, author))
        {
            return false;
        }
        let left = budget - 1;
        if backfill {
            self.backfill_author_trigger_budget = left;
        } else {
            self.observed_trigger_budget = left;
        }
        if left == 0 {
            // Logged once per exhaustion (not per subsequent message — the
            // `budget > 0` check above already suppresses those) so an
            // operator can see the trigger going inert for this interval,
            // rather than it degrading silently.
            debug!(
                sweep_interval_secs = self.identity_resync_config.sweep_interval_secs,
                backfill,
                "identity-sync: observed-author trigger budget exhausted for this interval"
            );
        }
        self.maybe_trigger_identity_sync(author.to_string(), identity_sync::SCOPE_ALL);
        true
    }

    /// G9 (l2-node 0.151.0): run the authors sampled from one backfill
    /// page (`note_backfilled_author`, ≤ `MAX_BACKFILLED_AUTHORS_PER_PAGE`)
    /// through `observe_author_for_identity_pull` — the same gate as live
    /// gossip, but against its OWN per-interval budget
    /// (`backfill_author_trigger_budget`, audit N3), so backfill and gossip
    /// cannot starve each other. Stops early once that budget is spent.
    fn observe_backfilled_authors(&mut self, authors: &[(String, u8)]) {
        for (author, msg_type) in authors {
            if self.backfill_author_trigger_budget == 0 {
                break;
            }
            self.observe_author_for_identity_pull(author, *msg_type, true);
        }
    }

    /// Channel-history backfill trigger (spec 1, l2-node 0.47.0+).
    /// See [`Self::subscribe_channel`] for the full trigger contract.
    /// Lazily pull one wallet's identity bundle (delegation/profile/follows)
    /// from peers the first time that wallet is seen on this node (P-1). This
    /// is per-wallet and deduped — NOT a network-wide transfer — and races
    /// `FANOUT` peers (first non-empty response wins; siblings cancelled).
    fn maybe_trigger_identity_sync(&mut self, wallet: String, scopes: u8) {
        if wallet.is_empty() || scopes == 0 {
            return;
        }
        if self.identity_sync_triggered.contains(&wallet) {
            return; // already pulled this session
        }
        self.identity_sync_triggered_insert(wallet.clone());
        // Any connected peer is a candidate — request-response negotiation
        // refuses non-supporters cleanly.
        let mut candidates: Vec<PeerId> = self.swarm.connected_peers().copied().collect();
        if candidates.is_empty() {
            // No peers yet — allow a future re-trigger when one connects.
            self.identity_sync_triggered_remove(&wallet);
            return;
        }
        use rand::seq::SliceRandom;
        candidates.shuffle(&mut rand::thread_rng());
        candidates.truncate(identity_sync::FANOUT);

        let request = identity_sync::IdentitySyncRequest {
            wallet: wallet.clone(),
            scopes,
            cursor: None,
            overlap_digest: Vec::new(),
            round: 0,
        };
        // Bound the pending-request map (audit MEDIUM-1, mirrors
        // `handle_snapshot_client_command`'s MAX_PENDING_SNAPSHOT_REQUESTS
        // pattern): a malicious peer that never replies, or a burst of
        // triggers racing FANOUT peers each, can otherwise grow this map
        // without limit while requests await their libp2p response/timeout.
        const MAX_PENDING_IDENTITY_SYNC_REQUESTS: usize = 8192;
        if self.pending_identity_sync_requests.len() >= MAX_PENDING_IDENTITY_SYNC_REQUESTS {
            warn!(
                pending = self.pending_identity_sync_requests.len(),
                wallet = %wallet,
                "identity-sync pending-request map at cap — skipping pull"
            );
            self.identity_sync_triggered_remove(&wallet);
            return;
        }
        // Logged only once the pull is actually going to be dispatched —
        // logging this before the cap check above (re-audit finding) meant
        // "triggering pull" was immediately followed by "skipping pull" for
        // every wallet under sustained cap pressure.
        info!(wallet = %wallet, scopes, fanout = candidates.len(), "identity-sync: triggering pull");
        for peer in candidates {
            let id = self
                .swarm
                .behaviour_mut()
                .identity_sync
                .send_request(&peer, request.clone());
            self.pending_identity_sync_requests.insert(
                id,
                IdentitySyncPending {
                    peer_id: peer,
                    wallet: wallet.clone(),
                    scopes,
                    pages_fetched: 0,
                    consecutive_unproductive_pages: 0,
                },
            );
        }
    }

    /// Handle inbound + outbound identity-sync request-response events (P-1).
    fn handle_identity_sync_event(
        &mut self,
        event: libp2p::request_response::Event<
            identity_sync::IdentitySyncRequest,
            identity_sync::IdentitySyncResponse,
        >,
    ) {
        use crate::messages::router::RouteResult;
        use libp2p::request_response::{Event, Message};
        match event {
            // --- Inbound request: serve the wallet's identity envelopes ---
            Event::Message {
                peer,
                message: Message::Request { request, channel, request_id: _ },
                connection_id: _,
            } => {
                // Reject a malformed/oversized subject before it is used as a
                // rate-limiter map key or DB prefix (DoS hardening). Don't echo
                // the (possibly large) string back.
                if !identity_sync::is_plausible_subject(&request.wallet) {
                    let _ = self.swarm.behaviour_mut().identity_sync.send_response(
                        channel,
                        identity_sync::IdentitySyncResponse {
                            wallet: String::new(),
                            envelopes: Vec::new(),
                            has_more: false,
                            next_cursor: None,
                            server_capped: true,
                            completeness_root: None,
                        },
                    );
                    return;
                }
                // l2-node 0.151.0: rolling budget per (peer, wallet) instead
                // of a lifetime counter; charged for envelopes AND rows
                // examined (`budget_charge`, minimum 1 — an empty or
                // out-of-scope page is not free). Refusals are not charged.
                let key = (peer, request.wallet.clone());
                let gcra = self.identity_sync_budget;
                let guard = match self.identity_sync_limits.try_acquire(
                    peer,
                    &key,
                    identity_sync::SERVER_MAX_CONCURRENT_PER_PEER,
                    &gcra,
                    Instant::now(),
                ) {
                    Ok(g) => Some(g),
                    Err(refusal) => {
                        self.count_sync_budget_refusal(refusal);
                        None
                    }
                };
                let response = if guard.is_none() {
                    identity_sync::capped_response(&request)
                } else {
                    let (resp, work) = identity_sync::build_response_metered(
                        &self.storage,
                        &request,
                        identity_sync::MAX_ENVELOPES_PER_RESPONSE,
                    );
                    self.identity_sync_limits.charge(
                        key,
                        reconcile::budget_charge(resp.envelopes.len(), work),
                        &gcra,
                        Instant::now(),
                    );
                    resp
                };
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .identity_sync
                    .send_response(channel, response)
                {
                    warn!(peer = %peer, wallet = %request.wallet, error = ?e, "identity-sync: send_response failed");
                }
                drop(guard);
            }
            // --- Inbound response: validate + apply, then page ---
            Event::Message {
                peer,
                message: Message::Response { request_id, response },
                connection_id: _,
            } => {
                let Some(pending) = self.pending_identity_sync_requests.remove(&request_id) else {
                    return;
                };
                if response.server_capped {
                    return;
                }
                if response.envelopes.is_empty() && !response.has_more {
                    return;
                }
                // Race-winner: cancel sibling requests for the same wallet.
                self.pending_identity_sync_requests
                    .retain(|_, p| !(p.wallet == pending.wallet && p.peer_id != peer));

                let env_count = response.envelopes.len();
                let mut admitted = 0usize;
                let mut dropped = 0usize;
                // Security-audit follow-up on W9: a malicious responder isn't
                // bound by `identity_sync::MAX_ENVELOPES_PER_RESPONSE` — it
                // can pack a raw wire response with far more envelopes (up to
                // libp2p's response-size ceiling) to force real Ed25519
                // verification work on every one of them before the W9
                // paging-budget counters below even see the page. Refuse to
                // verify ANY envelope in an oversized page — this protocol
                // violation is treated as fully unproductive, feeding the
                // SAME consecutive-unproductive-pages counter, so a peer
                // that keeps over-sending gets cut off within a few pages
                // without ever paying the verification cost.
                if env_count > identity_sync::MAX_ENVELOPES_PER_RESPONSE {
                    warn!(
                        peer = %peer, wallet = %pending.wallet, received = env_count,
                        expected_max = identity_sync::MAX_ENVELOPES_PER_RESPONSE,
                        "identity-sync: response exceeds this protocol's own max page size; refusing to verify, treating as unproductive"
                    );
                } else {
                    for env_bytes in response.envelopes {
                        // Smuggling defense: only apply identity envelopes of the
                        // requested scopes (every envelope is still signature-
                        // validated by the router below).
                        if !envelope_targets_scope(&env_bytes, pending.scopes) {
                            dropped += 1;
                            continue;
                        }
                        match self.router.process_synced_message(&env_bytes) {
                            RouteResult::Accepted { .. } | RouteResult::Duplicate => admitted += 1,
                            RouteResult::Rejected(reason) | RouteResult::Invalid(reason) => {
                                warn!(peer = %peer, wallet = %pending.wallet, reason = %reason, "identity-sync: envelope rejected by router");
                            }
                            // Key-epoch arbitration loss (0.143.0): a sync-path rejection.
                            RouteResult::KeyConflict(_) => {}
                            RouteResult::PowRequired { .. } => {}
                        }
                    }
                }
                info!(peer = %peer, wallet = %pending.wallet, received = env_count, admitted, dropped, has_more = response.has_more, "identity-sync: applied bundle");

                // Audit final pre-mainnet W9: requester-side paging budget.
                let pages_fetched = pending.pages_fetched + 1;
                let consecutive_unproductive_pages = if admitted > 0 {
                    0
                } else {
                    pending.consecutive_unproductive_pages + 1
                };
                if pages_fetched >= MAX_PAGES_PER_SESSION {
                    warn!(peer = %peer, wallet = %pending.wallet, pages_fetched, "identity-sync: hit page-count backstop; stopping this session");
                    return;
                }
                if consecutive_unproductive_pages >= MAX_CONSECUTIVE_UNPRODUCTIVE_PAGES {
                    warn!(peer = %peer, wallet = %pending.wallet, consecutive_unproductive_pages, "identity-sync: peer made no progress for too many consecutive pages; stopping this session");
                    return;
                }

                if response.has_more {
                    if let Some(cursor) = response.next_cursor {
                        let next_req = identity_sync::IdentitySyncRequest {
                            wallet: pending.wallet.clone(),
                            scopes: pending.scopes,
                            cursor: Some(cursor),
                            overlap_digest: Vec::new(),
                            round: 0,
                        };
                        let next_id = self
                            .swarm
                            .behaviour_mut()
                            .identity_sync
                            .send_request(&pending.peer_id, next_req);
                        self.pending_identity_sync_requests.insert(
                            next_id,
                            IdentitySyncPending {
                                peer_id: pending.peer_id,
                                wallet: pending.wallet,
                                scopes: pending.scopes,
                                pages_fetched,
                                consecutive_unproductive_pages,
                            },
                        );
                    }
                }
            }
            Event::OutboundFailure { peer, request_id, error, .. } => {
                if let Some(pending) = self.pending_identity_sync_requests.remove(&request_id) {
                    debug!(peer = %peer, wallet = %pending.wallet, error = ?error, "identity-sync: outbound failed; siblings may succeed");
                }
            }
            _ => {}
        }
    }

    /// Bounded reconciliation of the GLOBAL news feed (P-3). Pulls the last
    /// `news_max_age_days` of news from up to FANOUT peers (first non-empty
    /// wins), as soon as peers exist, then repeats every
    /// `news_catchup_interval_hours`.
    ///
    /// The repeat is what makes news propagation eventually consistent. Live
    /// gossip alone is best-effort: a node that is restarting, partitioned, or
    /// not yet meshed on the news topic simply never sees that broadcast, and
    /// before 0.119.0 nothing could recover it.
    fn maybe_trigger_news_backfill(&mut self) {
        if !self.backfill_config.enabled {
            return;
        }
        // A transient storage error must NOT count as a completed sync — return
        // without stamping `last_news_sync` so the next tick retries.
        if self
            .storage
            .prefix_iter_cf(crate::storage::schema::cf::NEWS_FEED, &[], 1)
            .is_err()
        {
            return;
        }
        // Previously this ran ONLY on a completely empty feed, and latched a
        // "never again" flag the moment the feed was non-empty. That made every
        // missed gossip message permanent: a node that was restarting, briefly
        // partitioned, or not yet meshed on the news topic when a post was
        // broadcast had no way to ever learn about it, because holding even one
        // post disqualified it from reconciling. Two nodes in the same mesh
        // drifted to 32 posts vs 4 with nothing able to close the gap.
        //
        // Now the first run happens as soon as peers exist (whether or not the
        // feed is empty — a cold join and a catch-up want the same request), and
        // subsequent runs repeat on `news_catchup_interval_hours`. Re-serving is
        // safe: the responder re-sends signed envelopes, the requester re-routes
        // them through the normal validation path, and storing an envelope the
        // node already has is idempotent.
        let due = match self.last_news_sync {
            None => true,
            Some(started) => {
                let hours = self.backfill_config.news_catchup_interval_hours;
                hours > 0 && started.elapsed() >= Duration::from_secs(hours * 3600)
            }
        };
        if !due {
            return;
        }
        let mut candidates: Vec<PeerId> = self.swarm.connected_peers().copied().collect();
        if candidates.is_empty() {
            return; // no peers yet — retry on a later tick
        }
        use rand::seq::SliceRandom;
        candidates.shuffle(&mut rand::thread_rng());
        candidates.truncate(news_sync::FANOUT);

        let max_age_secs = if self.backfill_config.news_max_age_days == 0 {
            u64::MAX
        } else {
            self.backfill_config
                .news_max_age_days
                .saturating_mul(24 * 3600)
        };
        let request = news_sync::NewsSyncRequest {
            max_age_secs,
            cursor: None,
            overlap_digest: Vec::new(),
            round: 0,
        };
        info!(
            fanout = candidates.len(),
            news_max_age_days = self.backfill_config.news_max_age_days,
            catchup = self.last_news_sync.is_some(),
            "news-sync: triggering bounded global-news reconciliation"
        );
        for peer in candidates {
            let id = self
                .swarm
                .behaviour_mut()
                .news_sync
                .send_request(&peer, request.clone());
            self.pending_news_sync_requests.insert(
                id,
                NewsSyncPending { peer_id: peer, pages_fetched: 0, consecutive_unproductive_pages: 0 },
            );
        }
        self.last_news_sync = Some(std::time::Instant::now());
    }

    /// Handle inbound + outbound news-sync request-response events (P-3).
    fn handle_news_sync_event(
        &mut self,
        event: libp2p::request_response::Event<
            news_sync::NewsSyncRequest,
            news_sync::NewsSyncResponse,
        >,
    ) {
        use crate::messages::router::RouteResult;
        use libp2p::request_response::{Event, Message};

        // A value, not a closure borrowing `self`: the response arm calls
        // `&mut self` methods before paging (G9).
        let window_secs = if self.backfill_config.news_max_age_days == 0 {
            u64::MAX
        } else {
            self.backfill_config
                .news_max_age_days
                .saturating_mul(24 * 3600)
        };

        match event {
            // --- Inbound request: serve recent news (windowed + rate-limited) ---
            Event::Message {
                peer,
                message: Message::Request { request, channel, request_id: _ },
                connection_id: _,
            } => {
                // l2-node 0.151.0: rolling budget per peer instead of a
                // lifetime counter (see `news_sync::NewsResponderLimits`).
                let gcra = self.news_sync_budget;
                let guard = match self.news_sync_limits.try_acquire(
                    peer,
                    &peer,
                    news_sync::SERVER_MAX_CONCURRENT_PER_PEER,
                    &gcra,
                    Instant::now(),
                ) {
                    Ok(g) => Some(g),
                    Err(refusal) => {
                        self.count_sync_budget_refusal(refusal);
                        None
                    }
                };
                let response = if guard.is_none() {
                    news_sync::capped_response()
                } else {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    let (resp, work) = news_sync::build_response_metered(
                        &self.storage,
                        &request,
                        news_sync::MAX_ENVELOPES_PER_RESPONSE,
                        now_ms,
                        window_secs,
                    );
                    self.news_sync_limits.charge(
                        peer,
                        reconcile::budget_charge(resp.envelopes.len(), work),
                        &gcra,
                        Instant::now(),
                    );
                    resp
                };
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .news_sync
                    .send_response(channel, response)
                {
                    warn!(peer = %peer, error = ?e, "news-sync: send_response failed");
                }
                drop(guard);
            }
            // --- Inbound response: validate + apply, then page ---
            Event::Message {
                peer,
                message: Message::Response { request_id, response },
                connection_id: _,
            } => {
                let Some(pending) = self.pending_news_sync_requests.remove(&request_id) else {
                    return;
                };
                if response.server_capped {
                    return;
                }
                if response.envelopes.is_empty() && !response.has_more {
                    return;
                }
                // Race-winner: cancel sibling requests to other peers.
                self.pending_news_sync_requests.retain(|_, p| p.peer_id == peer);

                let count = response.envelopes.len();
                let mut admitted = 0usize;
                let mut dropped = 0usize;
                // Security-audit follow-up on W9: see identity-sync's arm
                // above for the full rationale — refuse to verify ANY
                // envelope in a page that exceeds this protocol's own max
                // page size, treating it as unproductive rather than
                // paying the verification cost.
                let mut accepted_authors: Vec<(String, u8)> = Vec::new();
                if count > news_sync::MAX_ENVELOPES_PER_PAGE_WITH_RIDE_ALONGS {
                    warn!(
                        peer = %peer, received = count,
                        expected_max = news_sync::MAX_ENVELOPES_PER_PAGE_WITH_RIDE_ALONGS,
                        "news-sync: response exceeds this protocol's own max page size; refusing to verify, treating as unproductive"
                    );
                } else {
                    let deletion_min_ts = window_start_ms(window_secs);
                    for env_bytes in response.envelopes {
                        if !envelope_targets_news(&env_bytes) {
                            dropped += 1;
                            continue;
                        }
                        let is_deletion = is_deletion_request(&env_bytes);
                        match deletion_request_fit(&self.storage, &env_bytes, DeletionScope::News, deletion_min_ts) {
                            DeletionFit::Fits => {}
                            // Not progress, not a peer fault (W1/W4).
                            DeletionFit::Neutral => continue,
                            DeletionFit::Malformed => {
                                warn!(peer = %peer, "news-sync: malformed deletion request dropped");
                                dropped += 1;
                                continue;
                            }
                        }
                        match self.router.process_synced_message(&env_bytes) {
                            // A pending-only DeletionRequest, or one the router
                            // refused by policy, is neither progress nor a
                            // fault (W1/W4); an Invalid one is warned below.
                            RouteResult::Accepted { .. } if is_deletion && pending_only_deletion(&self.storage, &env_bytes) => {}
                            RouteResult::Rejected(_) if is_deletion => {}
                            RouteResult::Accepted { author, msg_type, .. } => {
                                admitted += 1;
                                note_backfilled_author(&mut accepted_authors, author, msg_type as u8);
                            }
                            RouteResult::Duplicate => admitted += 1,
                            RouteResult::Rejected(reason) | RouteResult::Invalid(reason) => {
                                warn!(peer = %peer, reason = %reason, "news-sync: envelope rejected by router");
                            }
                            // Key-epoch arbitration loss (0.143.0): a sync-path rejection.
                            RouteResult::KeyConflict(_) => {}
                            RouteResult::PowRequired { .. } => {}
                        }
                    }
                }
                // G9 (l2-node 0.151.0): authors of newly accepted news go
                // through the same identity-pull gate as live gossip.
                self.observe_backfilled_authors(&accepted_authors);
                info!(peer = %peer, received = count, admitted, dropped, has_more = response.has_more, "news-sync: applied batch");

                // Audit final pre-mainnet W9: requester-side paging budget —
                // stop asking this peer for more once it's clearly not
                // making progress, or unconditionally past a hard backstop.
                let pages_fetched = pending.pages_fetched + 1;
                let consecutive_unproductive_pages = if admitted > 0 {
                    0
                } else {
                    pending.consecutive_unproductive_pages + 1
                };
                if pages_fetched >= MAX_PAGES_PER_SESSION {
                    warn!(peer = %peer, pages_fetched, "news-sync: hit page-count backstop; stopping this session");
                    return;
                }
                if consecutive_unproductive_pages >= MAX_CONSECUTIVE_UNPRODUCTIVE_PAGES {
                    warn!(peer = %peer, consecutive_unproductive_pages, "news-sync: peer made no progress for too many consecutive pages; stopping this session");
                    return;
                }

                if response.has_more {
                    if let Some(cursor) = response.next_cursor {
                        let next_req = news_sync::NewsSyncRequest {
                            max_age_secs: window_secs,
                            cursor: Some(cursor),
                            overlap_digest: Vec::new(),
                            round: 0,
                        };
                        let next_id = self
                            .swarm
                            .behaviour_mut()
                            .news_sync
                            .send_request(&peer, next_req);
                        self.pending_news_sync_requests.insert(
                            next_id,
                            NewsSyncPending { peer_id: peer, pages_fetched, consecutive_unproductive_pages },
                        );
                    }
                }
            }
            Event::OutboundFailure { peer, request_id, error, .. } => {
                if self.pending_news_sync_requests.remove(&request_id).is_some() {
                    debug!(peer = %peer, error = ?error, "news-sync: outbound failed; siblings may succeed");
                }
            }
            _ => {}
        }
    }

    // ===== DM offline store-and-forward (spec 3, l2-node 0.69.0+) =====

    /// Re-subscribe to the DM gossip topics of this node's local users at
    /// startup (offline store-and-forward Phase 1). Subscribes the
    /// most-recently-active `max_local_subscriptions` first, so that — if the CF
    /// somehow exceeds the cap — the freshest users win the bounded slots.
    fn resubscribe_local_dm_users(&mut self) {
        const SCAN_CAP: usize = 200_000;
        let rows = match self
            .storage
            .prefix_iter_cf(schema::cf::LOCAL_DM_USERS, &[], SCAN_CAP)
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "resubscribe_local_dm_users: scan failed");
                return;
            }
        };
        if rows.is_empty() {
            return;
        }
        // Sort most-recently-active first, then bound to the configured cap.
        let mut users: Vec<(u64, String)> = rows
            .into_iter()
            .filter_map(|(k, v)| {
                let last = schema::decode_local_dm_user(&v).map(|(_, l)| l).unwrap_or(0);
                String::from_utf8(k).ok().map(|w| (last, w))
            })
            .collect();
        users.sort_unstable_by(|a, b| b.0.cmp(&a.0));
        let cap = self.dm_config.max_local_subscriptions;
        if cap > 0 && users.len() > cap {
            users.truncate(cap);
        }
        let count = users.len();
        for (_, wallet) in users {
            self.subscribe_dm(&wallet);
        }
        info!(count, "re-subscribed to local users' DM gossip topics (offline store-and-forward)");
    }

    /// One-time bounded backfill of a single wallet's missed DMs (Phase 2). Fires
    /// once per wallet per process — when that wallet first authenticates here —
    /// pulling its recent DMs from up to `FANOUT` peers (first non-empty wins).
    /// Covers the fresh-node / home-node-was-down case Phase 1 can't. Each
    /// request is node-signed + host-bound to its responder (`dm_sync::sign_request`),
    /// AND (audit W5) carries a wallet-signed claim proving the wallet itself
    /// authorized THIS node — without one, no responder will serve anything.
    fn maybe_trigger_dm_backfill(&mut self, wallet: &str, wallet_claim: Option<dm_sync::WalletAuthClaim>) {
        if self.dm_backfill_triggered.contains(wallet) {
            return;
        }
        // W5: resolve the freshest available wallet-signed authorization —
        // prefer one attached to THIS call, else fall back to one cached from
        // an earlier auth this session. Without one, retry on a later
        // registration call once one arrives — mirrors the "no peers
        // connected yet" early-return below (don't mark triggered).
        let Some(claim) = wallet_claim.or_else(|| self.wallet_claims.get(wallet).cloned()) else {
            return;
        };

        let mut candidates: Vec<PeerId> = self.swarm.connected_peers().copied().collect();
        if candidates.is_empty() {
            return; // no peers yet — retry on the wallet's next auth/registration
        }
        use rand::seq::SliceRandom;
        candidates.shuffle(&mut rand::thread_rng());
        candidates.truncate(dm_sync::FANOUT);

        let max_age_secs = if self.dm_config.backfill_max_age_days == 0 {
            u64::MAX
        } else {
            self.dm_config
                .backfill_max_age_days
                .saturating_mul(24 * 3600)
        };
        let network = self.topics.network_id().to_string();
        let now = now_ms();
        info!(
            %wallet,
            fanout = candidates.len(),
            backfill_max_age_days = self.dm_config.backfill_max_age_days,
            "dm-sync: triggering bounded DM backfill"
        );

        // Cache for the pagination-continuation arm + subsequent triggers this
        // session. Bound mirrors `dm_backfill_triggered` below (not a
        // security cap — worst case of clearing is one redundant re-sign
        // later).
        if self.wallet_claims.len() >= 100_000 {
            self.wallet_claims.clear();
        }
        self.wallet_claims.insert(wallet.to_string(), claim.clone());

        for peer in candidates {
            let request = dm_sync::sign_request(
                &self.signing_key,
                &network,
                &peer.to_string(),
                wallet,
                now,
                max_age_secs,
                None,
                Some(claim.clone()),
            );
            let id = self
                .swarm
                .behaviour_mut()
                .dm_sync
                .send_request(&peer, request);
            self.pending_dm_sync_requests.insert(
                id,
                DmSyncPending {
                    peer_id: peer,
                    wallet: wallet.to_string(),
                    pages_fetched: 0,
                    consecutive_unproductive_pages: 0,
                },
            );
        }
        // Mark triggered even if all requests ultimately fail — re-auth retries
        // are unnecessary noise; live gossip fills the gap once subscribed.
        // Bound the set (mirrors `identity_sync_triggered`); clearing only causes
        // a one-time redundant backfill later, which self-dedups via gossip.
        if self.dm_backfill_triggered.len() >= 100_000 {
            self.dm_backfill_triggered.clear();
        }
        self.dm_backfill_triggered.insert(wallet.to_string());
    }

    /// Handle inbound + outbound dm-sync request-response events (Phase 2).
    fn handle_dm_sync_event(
        &mut self,
        event: libp2p::request_response::Event<
            dm_sync::DmSyncRequest,
            dm_sync::DmSyncResponse,
        >,
    ) {
        use libp2p::request_response::{Event, Message};

        // Responder retention window: serve DMs no older than this. 0 = unlimited.
        let window_secs = || {
            if self.dm_config.retention_days == 0 {
                u64::MAX
            } else {
                self.dm_config.retention_days.saturating_mul(24 * 3600)
            }
        };

        match event {
            // --- Inbound request: authenticate, then serve the wallet's DMs ---
            Event::Message {
                peer,
                message: Message::Request { request, channel, request_id: _ },
                connection_id: _,
            } => {
                let network = self.topics.network_id().to_string();
                let responder_peer_id = self.swarm.local_peer_id().to_string();
                let now = now_ms();

                // AUTH FIRST — reject before any storage scan (DoS gate).
                if !dm_sync::verify_request_auth(&request, &responder_peer_id, &network, now, &peer) {
                    warn!(peer = %peer, wallet = %request.wallet, "dm-sync: request auth failed");
                    if let Err(e) = self
                        .swarm
                        .behaviour_mut()
                        .dm_sync
                        .send_response(channel, dm_sync::auth_failed_response())
                    {
                        warn!(peer = %peer, error = ?e, "dm-sync: send auth_failed response failed");
                    }
                    return;
                }

                // l2-node 0.151.0: rolling budget per peer instead of a
                // lifetime counter (see `dm_sync::DmResponderLimits`).
                let gcra = self.dm_sync_budget;
                let guard = match self.dm_sync_limits.try_acquire(
                    peer,
                    &peer,
                    dm_sync::SERVER_MAX_CONCURRENT_PER_PEER,
                    &gcra,
                    Instant::now(),
                ) {
                    Ok(g) => Some(g),
                    Err(refusal) => {
                        self.count_sync_budget_refusal(refusal);
                        None
                    }
                };
                let response = if guard.is_none() {
                    dm_sync::capped_response()
                } else {
                    let (resp, scanned_all, work) = dm_sync::build_response(
                        &self.storage,
                        &request.wallet,
                        &request,
                        dm_sync::MAX_ENVELOPES_PER_RESPONSE,
                        now,
                        window_secs(),
                    );
                    if !scanned_all {
                        warn!(
                            peer = %peer,
                            wallet = %request.wallet,
                            cap = dm_sync::MAX_CONVERSATIONS,
                            "dm-sync: wallet has more conversations than the scan cap; backfilled the first {} only (rest arrive via live gossip)",
                            dm_sync::MAX_CONVERSATIONS,
                        );
                    }
                    self.dm_sync_limits.charge(
                        peer,
                        reconcile::budget_charge(resp.envelopes.len(), work),
                        &gcra,
                        Instant::now(),
                    );
                    resp
                };
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .dm_sync
                    .send_response(channel, response)
                {
                    warn!(peer = %peer, error = ?e, "dm-sync: send_response failed");
                }
                drop(guard);
            }
            // --- Inbound response: validate + apply, then page ---
            Event::Message {
                peer,
                message: Message::Response { request_id, response },
                connection_id: _,
            } => {
                let pending = match self.pending_dm_sync_requests.remove(&request_id) {
                    Some(p) => p,
                    None => {
                        // A cancelled fanout sibling (l2-node 0.153.0): apply
                        // only its order-independent head envelopes
                        // (delegation, vault, settings, DM keys), no paging.
                        if let Some(wallet) = self.dm_sync_cancelled_siblings.remove(&request_id) {
                            if !response.auth_failed
                                && !response.server_capped
                                && response.envelopes.len()
                                    <= dm_sync::max_page_envelopes(true, !response.has_more)
                            {
                                let t = tally_dm_sync_envelopes(
                                    &self.router,
                                    &self.storage,
                                    &wallet,
                                    response.envelopes,
                                    0,
                                    true,
                                    &peer,
                                );
                                debug!(peer = %peer, admitted = t.admitted, dropped = t.dropped, "dm-sync: applied a cancelled sibling's head envelopes");
                            }
                        }
                        return;
                    }
                };
                if response.auth_failed {
                    // Our own request was rejected — a bug or clock skew. Don't
                    // hammer; live gossip still covers newly-arriving DMs.
                    warn!(peer = %peer, wallet = %pending.wallet, "dm-sync: responder rejected our auth");
                    return;
                }
                if response.server_capped {
                    return;
                }
                if response.envelopes.is_empty() && !response.has_more {
                    return;
                }
                // Race-winner: cancel sibling requests for this wallet to others.
                // Their first pages still arrive (l2-node 0.153.0): remember
                // them so their head envelopes are applied too.
                let wallet = pending.wallet.clone();
                let cancelled: Vec<libp2p::request_response::OutboundRequestId> = self
                    .pending_dm_sync_requests
                    .iter()
                    .filter(|(_, p)| p.peer_id != peer && p.wallet == wallet)
                    .map(|(id, _)| *id)
                    .collect();
                for id in cancelled {
                    if let Some(p) = self.pending_dm_sync_requests.remove(&id) {
                        // Only a session's first request can be cancelled
                        // (continuations are sent after the race is decided).
                        if p.pages_fetched == 0
                            && self.dm_sync_cancelled_siblings.len() < MAX_DM_SYNC_CANCELLED_SIBLINGS
                        {
                            self.dm_sync_cancelled_siblings.insert(id, p.wallet);
                        }
                    }
                }

                let count = response.envelopes.len();
                let mut tally = DmSyncTally::default();
                // Security-audit follow-up on W9: see identity-sync's arm
                // above for the full rationale — refuse to verify ANY
                // envelope in a page that exceeds this protocol's own max
                // page size, treating it as unproductive rather than
                // paying the verification cost. We always request revision
                // 1 (l2-node 0.153.0): the head is allowed only on the first
                // page (no cursor sent), the ride-alongs only on the final
                // page (round-1 audit N2).
                let page_bound = dm_sync::max_page_envelopes(pending.pages_fetched == 0, !response.has_more);
                if count > page_bound {
                    warn!(
                        peer = %peer, wallet = %wallet, received = count,
                        expected_max = page_bound,
                        "dm-sync: response exceeds this protocol's own max page size; refusing to verify, treating as unproductive"
                    );
                } else {
                    let deletion_min_ts =
                        window_start_ms(days_window_secs_zero_unlimited(self.dm_config.backfill_max_age_days));
                    tally = tally_dm_sync_envelopes(
                        &self.router,
                        &self.storage,
                        &wallet,
                        response.envelopes,
                        deletion_min_ts,
                        false,
                        &peer,
                    );
                }
                let DmSyncTally { admitted, dropped, neutral } = tally;
                info!(peer = %peer, wallet = %wallet, received = count, admitted, dropped, neutral, has_more = response.has_more, "dm-sync: applied batch");

                // Audit final pre-mainnet W9: requester-side paging budget.
                let pages_fetched = pending.pages_fetched + 1;
                let consecutive_unproductive_pages = if admitted > 0 {
                    0
                } else {
                    pending.consecutive_unproductive_pages + 1
                };
                if pages_fetched >= MAX_PAGES_PER_SESSION {
                    warn!(peer = %peer, wallet = %wallet, pages_fetched, "dm-sync: hit page-count backstop; stopping this session");
                    return;
                }
                if consecutive_unproductive_pages >= MAX_CONSECUTIVE_UNPRODUCTIVE_PAGES {
                    warn!(peer = %peer, wallet = %wallet, consecutive_unproductive_pages, "dm-sync: peer made no progress for too many consecutive pages; stopping this session");
                    return;
                }

                if response.has_more {
                    if let Some(cursor) = response.next_cursor {
                        let network = self.topics.network_id().to_string();
                        let max_age_secs = if self.dm_config.backfill_max_age_days == 0 {
                            u64::MAX
                        } else {
                            self.dm_config.backfill_max_age_days.saturating_mul(24 * 3600)
                        };
                        // W5: reuse the cached wallet claim (this arm doesn't
                        // go through register_local_dm_user, so there's no
                        // freshly-attached one to prefer).
                        let claim = self.wallet_claims.get(&wallet).cloned();
                        let next_req = dm_sync::sign_request(
                            &self.signing_key,
                            &network,
                            &peer.to_string(),
                            &wallet,
                            now_ms(),
                            max_age_secs,
                            Some(cursor),
                            claim,
                        );
                        let next_id = self
                            .swarm
                            .behaviour_mut()
                            .dm_sync
                            .send_request(&peer, next_req);
                        self.pending_dm_sync_requests.insert(
                            next_id,
                            DmSyncPending { peer_id: peer, wallet, pages_fetched, consecutive_unproductive_pages },
                        );
                    }
                }
            }
            Event::OutboundFailure { peer, request_id, error, .. } => {
                if let Some(p) = self.pending_dm_sync_requests.remove(&request_id) {
                    debug!(peer = %peer, wallet = %p.wallet, error = ?error, "dm-sync: outbound failed; siblings may succeed");
                }
                self.dm_sync_cancelled_siblings.remove(&request_id);
            }
            _ => {}
        }
    }

    /// Release the per-process in-flight dedup entry for `(wallet,
    /// channel_id)` once no sibling fanout request or paging continuation
    /// is still outstanding for it — mirrors
    /// `release_reconcile_trigger_if_no_siblings` exactly. Lets a future
    /// `federate_channel` call or the periodic retry sweep re-evaluate
    /// (and re-trigger if still due) rather than being blocked forever by
    /// this session's own dedup entry.
    fn release_private_channel_sync_trigger_if_no_siblings(&mut self, wallet: &str, channel_id: u64) {
        let still_pending = self
            .pending_private_channel_sync_requests
            .values()
            .any(|p| p.wallet == wallet && p.channel_id == channel_id);
        if !still_pending {
            self.private_channel_sync_triggered.remove(&(wallet.to_string(), channel_id));
        }
        // l2-node 0.149.0: an unsubscribe deferred while this session ran
        // (or a re-subscribe its replay caused) is applied now.
        self.reconcile_channel_lifecycle(channel_id);
    }

    /// Cache `claim` as `wallet`'s private-channel-sync claim unless a
    /// FRESHER one is already cached (l2-node 0.142.0 — "freshest per
    /// wallet"). Bounded at `MAX_CACHED_PCHANSYNC_CLAIMS`: when full, claims
    /// already past `WALLET_AUTH_MAX_AGE_SECS` (useless anyway) are dropped
    /// first, then the single oldest one — never the whole map (N3).
    fn cache_private_channel_sync_claim(&mut self, wallet: &str, claim: private_channel_sync::WalletAuthClaim) {
        if let Some(existing) = self.private_channel_sync_wallet_claims.get(wallet) {
            if existing.timestamp >= claim.timestamp {
                return;
            }
        } else if self.private_channel_sync_wallet_claims.len() >= MAX_CACHED_PCHANSYNC_CLAIMS {
            let now = now_ms();
            let max_age = private_channel_sync::WALLET_AUTH_MAX_AGE_SECS.saturating_mul(1000);
            self.private_channel_sync_wallet_claims
                .retain(|_, c| now.abs_diff(c.timestamp) <= max_age);
            if self.private_channel_sync_wallet_claims.len() >= MAX_CACHED_PCHANSYNC_CLAIMS {
                if let Some(oldest) = self
                    .private_channel_sync_wallet_claims
                    .iter()
                    .min_by_key(|(_, c)| c.timestamp)
                    .map(|(k, _)| k.clone())
                {
                    self.private_channel_sync_wallet_claims.remove(&oldest);
                }
            }
        }
        self.private_channel_sync_wallet_claims.insert(wallet.to_string(), claim);
    }

    /// `true` when `claim` is still usable now: inside the freshness window
    /// and (for a device-signed claim) its device not revoked at or after
    /// the presented delegation (N5).
    fn private_channel_sync_claim_usable(&self, wallet: &str, claim: &private_channel_sync::WalletAuthClaim) -> bool {
        now_ms().abs_diff(claim.timestamp)
            <= private_channel_sync::WALLET_AUTH_MAX_AGE_SECS.saturating_mul(1000)
            && private_channel_sync::device_claim_unrevoked(&self.storage, wallet, Some(claim))
    }

    /// A wallet presented a fresh, verified pchansync claim on an
    /// authenticated REST request or WS connect (l2-node 0.142.0, at most
    /// once per wallet per 60 s — gated in the API layer). Cache it and
    /// re-evaluate every private channel the wallet has local standing for
    /// here through the normal attempt throttle and completion due-gate —
    /// never the federate bypass, so an active client cannot defeat the
    /// 0.141.0 in-sync recheck interval.
    ///
    /// l2-node 0.150.0 (Phase E): the channels are the union of the
    /// wallet's `LOCAL_CHANNEL_FED` rows and its (verified)
    /// `LOCAL_CHANNEL_HOMES` rows, at most `MAX_CLAIM_REFRESH_CHANNELS`
    /// from each source, deduplicated by channel id. The claim is cached
    /// only when that union is non-empty (N3).
    fn refresh_private_channel_sync_claim(
        &mut self,
        wallet: &str,
        claim: Option<private_channel_sync::WalletAuthClaim>,
    ) {
        let Some(claim) = claim else { return };
        if !self.private_channel_sync_config.enabled {
            return;
        }
        let channels = self.private_sync_refresh_channels(wallet);
        // N3: a wallet with nothing federated and no local home here has
        // nothing to backfill — its claim is not cached at all.
        if channels.is_empty() {
            return;
        }
        self.cache_private_channel_sync_claim(wallet, claim);
        // One subscriber snapshot for the whole refresh (≤ 512 channels).
        let mut subscribers: RemoteSubscriberCache = None;
        for cid in channels {
            // `None`: the cached (freshest) claim is picked up inside.
            self.maybe_trigger_private_channel_sync_with(cid, wallet, None, false, &mut subscribers);
        }
    }

    /// The private channels a claim refresh re-evaluates for `wallet`
    /// (l2-node 0.150.0, Phase E): its `LOCAL_CHANNEL_FED` rows and its
    /// verified `LOCAL_CHANNEL_HOMES` rows (through the wallet index), at
    /// most `MAX_CLAIM_REFRESH_CHANNELS` from EACH source (so a wallet with
    /// many federations cannot starve its local-only channels), deduplicated
    /// by channel id. A read error of one source only drops that source.
    fn private_sync_refresh_channels(&self, wallet: &str) -> std::collections::BTreeSet<u64> {
        let prefix = crate::storage::schema::encode_local_channel_fed_prefix(wallet);
        let fed_rows = match self.storage.prefix_iter_cf(
            crate::storage::schema::cf::LOCAL_CHANNEL_FED,
            &prefix,
            MAX_CLAIM_REFRESH_CHANNELS,
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "private-channel-sync claim refresh: LOCAL_CHANNEL_FED read failed");
                Vec::new()
            }
        };
        let homes = match self
            .storage
            .local_home_channels_for_wallet(wallet, MAX_CLAIM_REFRESH_CHANNELS)
        {
            Ok(h) => h,
            Err(e) => {
                warn!(error = %e, "private-channel-sync claim refresh: local-homes index read failed");
                Vec::new()
            }
        };
        self.counters
            .add_private_sync_homes_pairs_evaluated(homes.len() as u64);
        let mut channels: std::collections::BTreeSet<u64> = fed_rows
            .iter()
            .filter_map(|(key, _)| {
                key.get(prefix.len()..)
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                    .map(u64::from_be_bytes)
            })
            .collect();
        channels.extend(homes);
        channels
    }

    /// Every topic some connected peer subscribes (any peer whose
    /// subscription announcement we hold — gossipsub tracks those even while
    /// this node is itself off the topic, e.g. while a lifecycle row is
    /// pending; mesh peers are a subset). ONE walk of `all_peers()`, which
    /// allocates per peer and costs O(sum of topics over peers): callers
    /// build it at most once per claim refresh / sweep tick / single
    /// trigger (lazily, through [`RemoteSubscriberCache`]) and look every
    /// channel up in it, never one walk per channel (round-1 audit W1).
    fn remote_subscribed_topics(&mut self) -> HashSet<libp2p::gossipsub::TopicHash> {
        self.remote_subscriber_walks = self.remote_subscriber_walks.saturating_add(1);
        self.swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .flat_map(|(_, topics)| topics.into_iter().cloned())
            .collect()
    }

    /// [`maybe_trigger_private_channel_sync_with`] for a single trigger (its
    /// own lazily built subscriber snapshot).
    ///
    /// [`maybe_trigger_private_channel_sync_with`]: Self::maybe_trigger_private_channel_sync_with
    fn maybe_trigger_private_channel_sync(
        &mut self,
        channel_id: u64,
        wallet: &str,
        wallet_claim: Option<private_channel_sync::WalletAuthClaim>,
        bypass: bool,
    ) {
        let mut subscribers: RemoteSubscriberCache = None;
        self.maybe_trigger_private_channel_sync_with(channel_id, wallet, wallet_claim, bypass, &mut subscribers);
    }

    /// One-time-per-due-window bounded backfill of a single private
    /// channel's missed history for `wallet` (closes the F2 backfill gap,
    /// l2-node 0.138.0+). Fires when a wallet federates a channel here
    /// (`federate_channel`, over `private_channel_sync_tx`) and from the
    /// periodic retry sweep (`retry_incomplete_private_channel_syncs`) for
    /// channels that haven't reached natural completion yet. Each request
    /// is node-signed + host-bound + channel-bound to its responder
    /// (`private_channel_sync::sign_request`), AND carries a wallet-signed
    /// claim proving the wallet authorized THIS node — without one, no
    /// responder will serve anything (mirrors dm-sync's audit-W5 gate).
    ///
    /// `bypass` (l2-node 0.142.0): only a `federate_channel` call carrying a
    /// fresh claim passes `true` (the 60 s-floored throttle bypass); the
    /// periodic sweep and the auth-path claim refresh pass `false`.
    ///
    /// `subscribers` (l2-node 0.150.0): the caller's lazily built snapshot of
    /// remotely subscribed topics for the no-host gate, shared across every
    /// channel a refresh or sweep tick evaluates.
    fn maybe_trigger_private_channel_sync_with(
        &mut self,
        channel_id: u64,
        wallet: &str,
        wallet_claim: Option<private_channel_sync::WalletAuthClaim>,
        bypass: bool,
        subscribers: &mut RemoteSubscriberCache,
    ) {
        if !self.private_channel_sync_config.enabled {
            return;
        }
        // This protocol only serves PRIVATE channels — public ones are
        // already covered by `reconcile`, which (correctly) refuses every
        // private-channel request. Mirrors `maybe_trigger_backfill`'s
        // equivalent guard in the opposite direction.
        if !reconcile::is_private_channel(&self.storage, channel_id) {
            return;
        }
        // l2-node 0.149.0 (plan §6): a wallet with no stake in the channel
        // on this node has nothing to backfill. A current member qualifies,
        // and so does a wallet with a `LOCAL_CHANNEL_HOMES` /
        // `LOCAL_CHANNEL_FED` row that is not (or no longer) a member here: a
        // stale replay (an old kick learned late) may have removed it while
        // its newer re-join is still missing — the healing walk is what
        // brings that re-join (the responder checks membership on ITS
        // side). Checked before any throttle state moves; a read error
        // skips (retried by the sweep).
        if !matches!(self.storage.wallet_has_local_channel_standing(channel_id, wallet), Ok(true)) {
            return;
        }
        // Cheap in-memory READS first (no state moves): a pair already in
        // flight, or one the attempt throttle would hold back anyway, needs
        // no further work — in particular not the no-host gate below.
        let key = (wallet.to_string(), channel_id);
        if self.private_channel_sync_triggered.contains(&key)
            || !self.private_channel_sync_throttle.ready_or_bypass(
                &key,
                Instant::now(),
                bypass && wallet_claim.is_some(),
            )
        {
            return;
        }
        // l2-node 0.150.0 (Phase E): a pair WITHOUT a `LOCAL_CHANNEL_FED`
        // row (standing only from membership or a `LOCAL_CHANNEL_HOMES`
        // row — e.g. a channel created here) may have no other host at all;
        // asking random peers would only waste fanout and tell them that
        // this wallet is in this channel. Such a pair is evaluated only
        // while some peer subscribes the channel's topic (a node that
        // federated it from us can still hold history we missed). Checked
        // before any throttle state moves. A FED read error counts as
        // "not federated" (the stricter gate).
        let fed = matches!(
            self.storage.exists_cf(
                crate::storage::schema::cf::LOCAL_CHANNEL_FED,
                &crate::storage::schema::encode_local_channel_fed_key(wallet, channel_id),
            ),
            Ok(true)
        );
        let topic_hash = libp2p::gossipsub::IdentTopic::new(gossip::channel_topic(
            self.topics.network_id(),
            channel_id,
        ))
        .hash();
        if !fed {
            if subscribers.is_none() {
                *subscribers = Some(self.remote_subscribed_topics());
            }
            if !subscribers.as_ref().is_some_and(|set| set.contains(&topic_hash)) {
                self.counters.inc_private_sync_skipped_no_host();
                debug!(channel_id, "private-channel-sync: no peer subscribes the channel; non-federated pair skipped");
                return;
            }
        }
        if !self.private_channel_sync_triggered.insert(key.clone()) {
            // Already in flight (or due-but-not-yet-resolved) this
            // session — don't pile another request on top of it.
            return;
        }

        let completed_at = self
            .storage
            .private_channel_sync_completed_at(wallet, channel_id);
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let due = channel_backfill_due(
            completed_at,
            now_secs,
            self.private_channel_sync_config.channel_catchup_interval_hours,
        );
        if !due {
            self.private_channel_sync_triggered.remove(&key);
            return;
        }
        // l2-node 0.141.0: attempt throttle (backoff after a dispatch, an
        // hourly recheck after a verified in-sync session). A federate call
        // carrying a fresh wallet claim may bypass it, but only once the
        // last dispatch is `FEDERATE_BYPASS_FLOOR` (60 s) old.
        let now_instant = Instant::now();
        if !self
            .private_channel_sync_throttle
            .ready_or_bypass(&key, now_instant, bypass && wallet_claim.is_some())
        {
            self.private_channel_sync_triggered.remove(&key);
            return;
        }

        // W5-equivalent: resolve the freshest available wallet-signed
        // authorization — prefer one attached to THIS call, else fall
        // back to one cached from an earlier federation this session.
        // Without one, retry on a later federation call once one arrives.
        // (l2-node 0.142.0: the FRESHER of the two — an older attached
        // claim must not shadow a newer cached one.)
        // N5: only USABLE claims compete (fresh, device not revoked), so a
        // fresher claim of a since-revoked device never shadows a valid one.
        let attached = wallet_claim.filter(|c| self.private_channel_sync_claim_usable(wallet, c));
        let cached = self
            .private_channel_sync_wallet_claims
            .get(wallet)
            .filter(|c| self.private_channel_sync_claim_usable(wallet, c))
            .cloned();
        let Some(claim) = private_channel_sync::freshest_claim(attached, cached) else {
            self.private_channel_sync_triggered.remove(&key);
            return;
        };
        // Code-audit finding (2026-10-01): `WALLET_AUTH_MAX_AGE_SECS` (300s)
        // bounds how long a wallet-signed claim stays valid — correct for
        // `dm_sync`, which has no periodic retry trigger at all (one claim,
        // one attempt, right after the auth that produced it). This
        // protocol DOES have a periodic retry sweep
        // (`retry_incomplete_private_channel_syncs`, every 30s tick,
        // `channel_catchup_interval_hours` due-gated — hours, not seconds),
        // which calls this function with `wallet_claim: None`, falling back
        // to whatever got cached at the LAST `federate_channel` call. Past
        // 5 minutes that cached claim is already expired by the time it
        // would reach a responder — sending it anyway wastes a full fanout
        // round-trip (and logs a `warn!` on both ends) for a request that
        // can only ever come back `auth_failed`. Check staleness locally
        // first and skip outright, same as the "no claim at all" case
        // above. This does NOT make the sweep able to complete a backfill
        // autonomously past 5 minutes post-federation — by design, a fresh
        // wallet signature requires the wallet to actually be present to
        // sign one. Genuine completion past that window happens the next
        // time the user's own client calls `/federate` again (which mints
        // a fresh claim) — the sweep's real job is covering the common
        // case where the FIRST attempt (at federation time) didn't finish
        // within its own 5-minute window, not guaranteeing eventual
        // completion with no further client activity ever again.
        if now_ms().abs_diff(claim.timestamp)
            > private_channel_sync::WALLET_AUTH_MAX_AGE_SECS.saturating_mul(1000)
        {
            self.private_channel_sync_triggered.remove(&key);
            return;
        }

        // l2-node 0.149.0 (plan §6): the persisted resume row decides where
        // this session starts — a same-peer continuation (one request to
        // the peer that issued the cursors), a high-water catch-up, or a
        // fresh walk from the first page.
        // A wallet that is NOT a current member here (standing only from a
        // home or federation row) is running a HEALING walk: the re-join it
        // must recover may predate any mark, so it always walks afresh from
        // the first page (security round 2, B1).
        let healing = !reconcile::is_channel_member(&self.storage, channel_id, wallet);
        let (start, resume_seed) = self.plan_private_channel_sync_start(wallet, channel_id, healing);
        let from_row = !matches!(start, private_channel_sync::ResumeStart::Fresh);
        let (mut seed_session, resume_peer) = match start {
            private_channel_sync::ResumeStart::Fresh => (private_channel_sync::SyncSession::default(), None),
            private_channel_sync::ResumeStart::Resume { peer, session } => (session, Some(peer)),
            private_channel_sync::ResumeStart::CatchUp { session } => (session, None),
        };
        // Round 4 W3: a ForwardOnly member's fanout start begins its chat
        // phase at its own join floor (never for a same-peer continuation
        // or a healing walk).
        if resume_peer.is_none() && !healing {
            if let Some(floor) = self.forward_only_chat_floor(channel_id, wallet) {
                private_channel_sync::apply_chat_floor(&mut seed_session, floor);
            }
        }

        // Candidate selection: GossipSub mesh peers for this channel's
        // topic; for a federated pair, fall back to any connected peer if
        // the mesh is sparse. A non-federated pair (l2-node 0.150.0) asks
        // ONLY peers subscribed to the topic (mesh first, then any peer
        // that announced the subscription) — never an arbitrary connected
        // peer, which would receive the signed wallet claim and the channel
        // id with nothing to give. A same-peer continuation asks only that
        // peer.
        let mut candidates: Vec<PeerId> = match resume_peer {
            Some(peer) => vec![peer],
            None => self
                .swarm
                .behaviour()
                .gossipsub
                .mesh_peers(&topic_hash)
                .copied()
                .collect(),
        };
        if resume_peer.is_none() && !fed && candidates.len() < private_channel_sync::FANOUT {
            for (p, topics) in self.swarm.behaviour().gossipsub.all_peers() {
                if candidates.len() >= private_channel_sync::FANOUT * 2 {
                    break;
                }
                if topics.iter().any(|t| **t == topic_hash) && !candidates.contains(p) {
                    candidates.push(*p);
                }
            }
        }
        if resume_peer.is_none() && fed && candidates.len() < private_channel_sync::FANOUT {
            for p in self.swarm.connected_peers() {
                if !candidates.contains(p) {
                    candidates.push(*p);
                }
                if candidates.len() >= private_channel_sync::FANOUT * 2 {
                    break;
                }
            }
        }
        if candidates.is_empty() {
            debug!(
                channel_id, %wallet,
                "private-channel-sync: no candidate peers; cold-start will retry on next federation/sweep"
            );
            self.private_channel_sync_triggered.remove(&key);
            return;
        }
        use rand::seq::SliceRandom;
        candidates.shuffle(&mut rand::thread_rng());
        candidates.truncate(private_channel_sync::FANOUT);

        let max_age_secs = if self.private_channel_sync_config.max_age_days == 0 {
            u64::MAX
        } else {
            self.private_channel_sync_config
                .max_age_days
                .saturating_mul(24 * 3600)
        };
        let network = self.topics.network_id().to_string();
        let now = now_ms();
        info!(
            channel_id,
            fanout = candidates.len(),
            "private-channel-sync: triggering bounded private-channel backfill"
        );

        // Cache for the pagination-continuation arm + subsequent triggers
        // this session. This map has its own independent 100k clear-all
        // bound (not a security cap — worst case of clearing is one
        // redundant re-sign later); `private_channel_sync_triggered`
        // (below) is NOT bounded the same way — unlike `dm_backfill_
        // triggered`, its entries are actively removed by
        // `release_private_channel_sync_trigger_if_no_siblings` on every
        // response/failure path, so it self-limits to roughly the number
        // of in-flight (wallet, channel) pairs rather than growing
        // unboundedly over the process lifetime.
        self.cache_private_channel_sync_claim(wallet, claim.clone());

        // l2-node 0.141.0: stamp the attempt HERE — after every early
        // return above (no claim, stale claim, no candidates), right before
        // the requests are actually sent. Stamping earlier would burn a
        // backoff step on an attempt that never happened.
        self.private_channel_sync_throttle
            .on_dispatch(key.clone(), now_instant, budget::random_jitter());
        self.counters.inc_private_sync_attempts_dispatched();
        if from_row {
            self.counters.inc_private_sync_resumed_sessions();
            debug!(
                %wallet, channel_id,
                same_peer = resume_peer.is_some(),
                sessions = resume_seed.as_ref().map(|s| s.sessions),
                "private-channel-sync: session starts from the persisted resume row"
            );
        }
        let (cursor, meta_cursor, meta_done) = seed_session.request_cursors();

        for peer in candidates {
            let request = private_channel_sync::sign_request(
                &self.signing_key,
                &network,
                &peer.to_string(),
                wallet,
                channel_id,
                now,
                max_age_secs,
                cursor.clone(),
                Some(claim.clone()),
            );
            // Walk ALL metadata first (R3-1, raw keyset paging); a responder
            // that predates metadata paging ignores this and answers with
            // its legacy first page. A session seeded from a resume row
            // starts at its stored position (an ordinary continuation
            // request on the wire).
            let request = private_channel_sync::PrivateChannelSyncRequest {
                meta_paging: true,
                meta_cursor: meta_cursor.clone(),
                meta_done,
                ..request
            };
            let id = self
                .swarm
                .behaviour_mut()
                .private_channel_sync
                .send_request(&peer, request);
            self.pending_private_channel_sync_requests.insert(
                id,
                PrivateChannelSyncPending {
                    peer_id: peer,
                    wallet: wallet.to_string(),
                    channel_id,
                    accepted_base: seed_session.accepted_total,
                    session: seed_session.clone(),
                    resume: resume_seed.clone(),
                    same_peer_resume: resume_peer.is_some(),
                },
            );
        }
    }

    /// ForwardOnly chat floor for a CURRENT member's fanout start (round 4,
    /// W3): `min(own CHANNEL_MEMBERS joined_at, earliest ChannelJoin
    /// timestamp in the member's CHANNEL_MEMBERSHIP_INDEX) −
    /// catchup_overlap_hours`, as a chat cursor (`CHANNEL_MSGS` is keyed by
    /// the signed envelope timestamp, msg_id zeroed). Uses only this node's
    /// own stored membership. `None` (no floor) for a FullHistory channel
    /// (`history_visibility == 1`), the creator, a non-member, or a member
    /// whose join is not recorded in the index: the local `joined_at` alone
    /// can be LATER than the responder's (a federation stamps its own
    /// time), and flooring there could skip rows the member may read. Every
    /// responder sets its floor at or after the signed join it applied, so
    /// the earliest indexed join never lies past it.
    fn forward_only_chat_floor(
        &self,
        channel_id: u64,
        wallet: &str,
    ) -> Option<private_channel_sync::PrivateChannelSyncCursor> {
        if reconcile::channel_history_visibility(&self.storage, channel_id) == Some(1) {
            return None;
        }
        let creator = self
            .storage
            .get_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes())
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|m| m.get("creator").and_then(|c| c.as_str()).map(str::to_string));
        if creator.as_deref() == Some(wallet) {
            return None;
        }
        let joined_ms = reconcile::member_joined_at(&self.storage, channel_id, wallet)?.saturating_mul(1000);
        let first_join = self
            .storage
            .membership_index_state(channel_id, wallet)
            .ok()
            .flatten()?
            .rows
            .iter()
            .filter(|(ty, _, _)| *ty == crate::messages::types::MessageType::ChannelJoin as u8)
            .map(|(_, ts, _)| *ts)
            .min()?;
        let overlap_ms = self.private_channel_sync_config.catchup_overlap_hours.saturating_mul(3_600_000);
        Some(private_channel_sync::PrivateChannelSyncCursor {
            after_lamport_ts: joined_ms.min(first_join).saturating_sub(overlap_ms),
            after_msg_id: [0u8; 32],
        })
    }

    /// Where a new private-channel-sync session for `(wallet, channel_id)`
    /// starts (l2-node 0.149.0, plan §6): reads and validates the persisted
    /// resume row and applies `private_channel_sync::plan_resume`. The seed
    /// is `None` when the resume cursor is off (`resume_ttl_hours = 0`):
    /// nothing is read or written and every session starts fresh.
    fn plan_private_channel_sync_start(
        &self,
        wallet: &str,
        channel_id: u64,
        force_fresh: bool,
    ) -> (private_channel_sync::ResumeStart, Option<private_channel_sync::ResumeSeed>) {
        let ttl_hours = self.private_channel_sync_config.resume_ttl_hours;
        if ttl_hours == 0 {
            return (private_channel_sync::ResumeStart::Fresh, None);
        }
        let now = now_ms();
        if force_fresh {
            let (start, seed) = private_channel_sync::fresh_start(now);
            return (start, Some(seed));
        }
        let row = self
            .storage
            .private_channel_sync_resume_raw(wallet, channel_id)
            .and_then(|raw| {
                let row = private_channel_sync::decode_resume_row(&raw, now);
                if row.is_none() {
                    debug!(%wallet, channel_id, "private-channel-sync: resume row does not validate; starting fresh");
                }
                row
            });
        let (start, seed) = private_channel_sync::plan_resume(
            row.as_ref(),
            now,
            ttl_hours,
            self.private_channel_sync_config.catchup_overlap_hours,
            |p| self.swarm.is_connected(p),
        );
        (start, Some(seed))
    }

    /// Persist the resume row after an applied private-sync page (l2-node
    /// 0.149.0, plan §6) — exactly one put. Skipped (nothing written) when
    /// the wallet has no stake in the channel here any more (not a member,
    /// no `LOCAL_CHANNEL_HOMES` / `LOCAL_CHANNEL_FED` row): a page that
    /// arrives after a genuine leave or a purge must not leave an orphan
    /// row behind, while a local home whose membership a stale replay
    /// removed still runs its healing walk (from the first page each time;
    /// its row is kept for when the membership is restored).
    #[allow(clippy::too_many_arguments)]
    fn persist_private_channel_sync_resume(
        &self,
        wallet: &str,
        channel_id: u64,
        peer: &PeerId,
        session: &private_channel_sync::SyncSession,
        step: &private_channel_sync::NextStep,
        response: &private_channel_sync::PrivateChannelSyncResponse,
        seed: &private_channel_sync::ResumeSeed,
    ) {
        if !matches!(self.storage.wallet_has_local_channel_standing(channel_id, wallet), Ok(true)) {
            return;
        }
        let row = private_channel_sync::resume_row_after_page(session, step, response, seed, peer, now_ms());
        self.write_private_channel_sync_resume(wallet, channel_id, &row);
    }

    /// Encode and store one resume row (errors are logged without the
    /// wallet: the pair (wallet, private channel) is not logged above debug).
    fn write_private_channel_sync_resume(
        &self,
        wallet: &str,
        channel_id: u64,
        row: &private_channel_sync::ResumeRow,
    ) {
        match serde_json::to_vec(row) {
            Ok(bytes) => {
                if let Err(e) = self.storage.put_private_channel_sync_resume(wallet, channel_id, &bytes) {
                    warn!(channel_id, error = %e, "private-channel-sync: failed to persist the resume row");
                }
            }
            Err(e) => warn!(channel_id, error = %e, "private-channel-sync: failed to encode the resume row"),
        }
    }

    /// The stored unfinished walk of a same-peer RESUME session, if the
    /// resume cursor is on and the row still describes one.
    fn resumed_walk_row(&self, pending: &PrivateChannelSyncPending, now: u64) -> Option<private_channel_sync::ResumeRow> {
        if !pending.same_peer_resume || pending.resume.is_none() {
            return None;
        }
        self.storage
            .private_channel_sync_resume_raw(&pending.wallet, pending.channel_id)
            .and_then(|raw| private_channel_sync::decode_resume_row(&raw, now))
            .filter(|row| row.phase.is_some())
    }

    /// The stored peer rejected a same-peer RESUME session's auth: clear the
    /// stored walk's position, keeping its high-water mark, so the next
    /// trigger fans out instead of asking the same peer again (audit S2).
    fn abandon_private_channel_sync_walk(&self, pending: &PrivateChannelSyncPending) {
        let now = now_ms();
        let Some(row) = self.resumed_walk_row(pending, now) else { return };
        debug!(channel_id = pending.channel_id, "private-channel-sync: resume peer rejected the walk; next session fans out");
        let abandoned = private_channel_sync::resume_row_abandon_walk(&row, now);
        self.write_private_channel_sync_resume(&pending.wallet, pending.channel_id, &abandoned);
    }

    /// A same-peer RESUME session ended (`server_capped`, a failed or timed
    /// out request, or an early finish) — `session` is its state at that
    /// point. Classified by `private_channel_sync::resume_session_outcome`:
    /// a session that took a verified envelope is progress, a zero-envelope
    /// cursor move is neutral, anything else is a STALL — counted, and the
    /// walk is abandoned only after `MAX_RESUME_STALLS` consecutive stalls
    /// (a peer whose budget is still refilling must not cost the walk its
    /// position).
    fn note_private_channel_sync_stall(
        &self,
        pending: &PrivateChannelSyncPending,
        session: &private_channel_sync::SyncSession,
    ) {
        let Some(seed) = pending.resume.as_ref() else { return };
        if private_channel_sync::resume_session_outcome(session, seed) != private_channel_sync::SessionOutcome::Stall {
            return;
        }
        let now = now_ms();
        let Some(row) = self.resumed_walk_row(pending, now) else { return };
        let next = private_channel_sync::resume_row_after_stall(&row, now);
        if next.phase.is_none() {
            debug!(channel_id = pending.channel_id, stalls = private_channel_sync::MAX_RESUME_STALLS, "private-channel-sync: resumed walk stalled repeatedly with its peer; next session fans out");
        }
        self.write_private_channel_sync_resume(&pending.wallet, pending.channel_id, &next);
    }

    /// Handle inbound + outbound private-channel-sync request-response
    /// events (closes the F2 backfill gap, l2-node 0.138.0+).
    fn handle_private_channel_sync_event(
        &mut self,
        event: libp2p::request_response::Event<
            private_channel_sync::PrivateChannelSyncRequest,
            private_channel_sync::PrivateChannelSyncResponse,
        >,
    ) {
        use crate::messages::router::RouteResult;
        use libp2p::request_response::{Event, Message};

        match event {
            // --- Inbound request: authenticate (incl. membership), then serve ---
            Event::Message {
                peer,
                message: Message::Request { request, channel, request_id: _ },
                connection_id: _,
            } => {
                let network = self.topics.network_id().to_string();
                let responder_peer_id = self.swarm.local_peer_id().to_string();
                let now = now_ms();

                // AUTH FIRST — reject before any storage scan (DoS gate).
                // Security-audit finding (2026-10-01): split into a pure-
                // crypto check (no storage access) run BEFORE `try_acquire`,
                // and a separate storage-touching membership check run only
                // AFTER a concurrency slot is granted — a peer with no valid
                // membership for anything could otherwise force two RocksDB
                // point-lookups per request with no per-peer rate cap.
                if !private_channel_sync::verify_request_crypto_auth(
                    &request,
                    &responder_peer_id,
                    &network,
                    now,
                    &peer,
                ) {
                    warn!(peer = %peer, channel_id = request.channel_id, wallet = %request.wallet, "private-channel-sync: request auth failed");
                    if let Err(e) = self
                        .swarm
                        .behaviour_mut()
                        .private_channel_sync
                        .send_response(channel, private_channel_sync::auth_failed_response(request.channel_id))
                    {
                        warn!(peer = %peer, error = ?e, "private-channel-sync: send auth_failed response failed");
                    }
                    return;
                }

                // Per-peer concurrency + rolling budget (l2-node 0.141.0;
                // refusals are never charged).
                let budget = self.private_channel_sync_budget;
                let guard = match self.private_channel_sync_limits.try_acquire(
                    peer,
                    private_channel_sync::SERVER_MAX_CONCURRENT_PER_PEER,
                    &budget,
                    Instant::now(),
                ) {
                    Ok(g) => Some(g),
                    Err(refusal) => {
                        self.count_budget_refusal(refusal, false);
                        debug!(peer = %peer, channel_id = request.channel_id, ?refusal, "private-channel-sync: refused; responding server_capped");
                        None
                    }
                };
                let Some(guard) = guard else {
                    if let Err(e) = self
                        .swarm
                        .behaviour_mut()
                        .private_channel_sync
                        .send_response(channel, private_channel_sync::capped_response(request.channel_id))
                    {
                        warn!(peer = %peer, error = ?e, "private-channel-sync: send capped response failed");
                    }
                    return;
                };

                // Gate 5 (membership + genuinely-private-channel), the one
                // storage-touching check — re-verified fresh on every
                // request, never cached.
                // l2-node 0.142.0: a device-signed claim's device must not
                // be revoked on this node (storage half of the claim check).
                if !private_channel_sync::verify_request_membership(
                    &self.storage,
                    request.channel_id,
                    &request.wallet,
                ) || !private_channel_sync::device_claim_unrevoked(
                    &self.storage,
                    &request.wallet,
                    request.wallet_claim.as_ref(),
                ) {
                    warn!(peer = %peer, channel_id = request.channel_id, wallet = %request.wallet, "private-channel-sync: membership check failed");
                    if let Err(e) = self
                        .swarm
                        .behaviour_mut()
                        .private_channel_sync
                        .send_response(channel, private_channel_sync::auth_failed_response(request.channel_id))
                    {
                        warn!(peer = %peer, error = ?e, "private-channel-sync: send auth_failed response failed");
                    }
                    return;
                }

                // Build OFF the swarm event loop (round 4: a metadata or
                // chat page is up to a few hundred RocksDB reads; done
                // inline it stalled every other peer's gossip). A node-wide
                // build slot bounds the blocking-pool use; none free →
                // `server_capped` for a session-starting request, a bounded
                // wait for a continuation (round-5 C-W1). `meta_done`
                // without a cursor is the first chat page after this
                // session's metadata phase — a continuation too.
                let continuation = request.is_continuation();
                let slot = self.responder_build_slot(continuation);
                if matches!(slot, BuildSlot::Refuse) {
                    if let Err(e) = self
                        .swarm
                        .behaviour_mut()
                        .private_channel_sync
                        .send_response(channel, private_channel_sync::capped_response(request.channel_id))
                    {
                        warn!(peer = %peer, error = ?e, "private-channel-sync: send capped response failed");
                    }
                    return;
                }
                let storage = self.storage.clone();
                let limits = Arc::clone(&self.private_channel_sync_limits);
                let tx = self.deferred_response_tx.clone();
                // `Ok` = build slot; `Err` = a continuation timed out waiting
                // (the waiter slot rides along with the capped response).
                let run = move |slot: Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::OwnedSemaphorePermit>| {
                    let build_permit = match slot {
                        Ok(p) => p,
                        Err(waiter) => {
                            let _ = tx.send(DeferredResponse::PrivateChannelSync {
                                peer,
                                channel,
                                response: private_channel_sync::capped_response(request.channel_id),
                                _guard: guard,
                                _build_permit: waiter,
                            });
                            return;
                        }
                    };
                    tokio::task::spawn_blocking(move || {
                        let (response, work) = private_channel_sync::build_response_metered(
                            &storage,
                            &request,
                            private_channel_sync::MAX_ENVELOPES_PER_RESPONSE,
                            now / 1000,
                            u64::MAX,
                        );
                        // Charge scan work as well as envelopes sent, minimum
                        // 1 per request (empty / garbage-cursor pages are not
                        // free). Charged here, before the response is queued,
                        // so the peer's next request already sees it.
                        limits.charge(
                            peer,
                            reconcile::budget_charge(response.envelopes.len(), work),
                            &budget,
                            Instant::now(),
                        );
                        // The loop may be shutting down (receiver gone): the
                        // response, guard and slot are simply dropped.
                        let _ = tx.send(DeferredResponse::PrivateChannelSync {
                            peer,
                            channel,
                            response,
                            _guard: guard,
                            _build_permit: build_permit,
                        });
                    });
                };
                match slot {
                    BuildSlot::Now(p) => run(Ok(p)),
                    BuildSlot::Wait(w) => {
                        let permits = self.responder_build_permits.clone();
                        tokio::spawn(async move { run(wait_for_build_slot(permits, w).await) });
                    }
                    BuildSlot::Refuse => {}
                }
            }
            // --- Inbound response: validate + apply, then page ---
            Event::Message {
                peer,
                message: Message::Response { request_id, response },
                connection_id: _,
            } => {
                let pending = match self.pending_private_channel_sync_requests.remove(&request_id) {
                    Some(p) => p,
                    None => return,
                };
                if response.auth_failed {
                    debug!(peer = %peer, wallet = %pending.wallet, channel_id = pending.channel_id, "private-channel-sync: responder rejected our auth");
                    self.abandon_private_channel_sync_walk(&pending);
                    self.release_private_channel_sync_trigger_if_no_siblings(&pending.wallet, pending.channel_id);
                    return;
                }
                // l2-node 0.149.0: the channel's local data is being purged
                // (the session was dispatched before the purge started).
                // Applying the page now would leave rows behind the purge
                // cursor; drop it — nothing is lost, the channel is going.
                if matches!(self.storage.private_channel_purge_in_progress(pending.channel_id), Ok(true)) {
                    debug!(channel_id = pending.channel_id, "private-channel-sync: page dropped, local cleanup of the channel in progress");
                    self.release_private_channel_sync_trigger_if_no_siblings(&pending.wallet, pending.channel_id);
                    return;
                }
                if response.server_capped {
                    self.note_private_channel_sync_stall(&pending, &pending.session);
                    self.release_private_channel_sync_trigger_if_no_siblings(&pending.wallet, pending.channel_id);
                    return;
                }
                // An empty, finished FIRST response: this peer knows nothing
                // about the pair — done, not complete, and no evidence of
                // anything. l2-node 0.141.0: limited to the session's FIRST
                // response (`session == default`) so an empty FINAL chat
                // page — after a productive OR an all-duplicate metadata
                // phase — reaches `advance` and records COMPLETE or
                // IN_SYNC. (Siblings were already cancelled by this peer's
                // first response, so this changes no cancellation.)
                if private_channel_sync::is_empty_first_response(&response, &pending.session) {
                    self.release_private_channel_sync_trigger_if_no_siblings(&pending.wallet, pending.channel_id);
                    return;
                }
                // Race-winner: cancel sibling requests for this (wallet, channel).
                let wallet = pending.wallet.clone();
                let channel_id = pending.channel_id;
                self.pending_private_channel_sync_requests.retain(|_, p| {
                    p.peer_id == peer || p.wallet != wallet || p.channel_id != channel_id
                });

                // Two-phase session state (round 4); the verified positions
                // of this page are recorded into it below (l2-node 0.149.0).
                let mut session = pending.session.clone();
                let count = response.envelopes.len();
                session.envelopes_seen = session.envelopes_seen.saturating_add(count);
                let mut admitted = 0usize;
                let mut accepted = 0usize;
                let mut dropped = 0usize;
                // In-sync evidence (l2-node 0.141.0): byte-verified
                // duplicates vs anything that is not clean evidence.
                let mut verified_dups = 0usize;
                let mut tainted = false;
                if count > private_channel_sync::MAX_ENVELOPES_PER_RESPONSE {
                    tainted = true;
                    warn!(
                        peer = %peer, %wallet, channel_id, received = count,
                        expected_max = private_channel_sync::MAX_ENVELOPES_PER_RESPONSE,
                        "private-channel-sync: response exceeds this protocol's own max page size; refusing to verify, treating as unproductive"
                    );
                } else {
                    let deletion_min_ts = window_start_ms(days_window_secs_zero_unlimited(
                        self.private_channel_sync_config.max_age_days,
                    ));
                    for env_bytes in &response.envelopes {
                        if !private_channel_sync::envelope_is_private_channel_sync_type(env_bytes)
                            || !envelope_targets_channel(env_bytes, channel_id)
                        {
                            dropped += 1;
                            tainted = true;
                            continue;
                        }
                        let is_deletion = is_deletion_request(env_bytes);
                        match deletion_request_fit(&self.storage, env_bytes, DeletionScope::Channel(channel_id), deletion_min_ts) {
                            DeletionFit::Fits => {}
                            // Neither progress nor taint (W1/W4).
                            DeletionFit::Neutral => continue,
                            DeletionFit::Malformed => {
                                dropped += 1;
                                tainted = true;
                                continue;
                            }
                        }
                        match self.router.process_synced_message(env_bytes) {
                            RouteResult::Accepted { .. } if is_deletion && pending_only_deletion(&self.storage, env_bytes) => {}
                            // Policy refusal: neutral. `Invalid` taints below.
                            RouteResult::Rejected(_) if is_deletion => {}
                            // Banned / muted author (0.152.0, B1): neutral.
                            RouteResult::Rejected(ref reason)
                                if crate::messages::router::is_neutral_sync_refusal(reason) => {}
                            RouteResult::Accepted { .. } => {
                                admitted += 1;
                                accepted += 1;
                                // Stored and verified by THIS node: the only
                                // source of the resume high-water mark.
                                session.record_verified(response.meta_phase, env_bytes);
                            }
                            RouteResult::Duplicate => {
                                admitted += 1;
                                if duplicate_is_verified(&self.storage, env_bytes) {
                                    verified_dups += 1;
                                    session.record_verified(response.meta_phase, env_bytes);
                                } else {
                                    tainted = true;
                                }
                            }
                            RouteResult::Rejected(reason) | RouteResult::Invalid(reason) => {
                                tainted = true;
                                warn!(peer = %peer, reason = %reason, "private-channel-sync: envelope rejected by router");
                            }
                            RouteResult::PowRequired { .. } => tainted = true,
                            // Key-epoch arbitration loss (0.143.0): a sync-path rejection.
                            RouteResult::KeyConflict(_) => tainted = true,
                        }
                    }
                }
                info!(peer = %peer, channel_id, received = count, admitted, dropped, has_more = response.has_more, "private-channel-sync: applied batch");

                // Two-phase state machine (round 4): per-phase page
                // budgets, strictly advancing cursors, no metadata page
                // after the chat phase started; completion only after the
                // chat phase ends with >= 1 `Accepted` in the session.
                session.record_evidence(verified_dups, tainted);
                let step = session.advance(&response, admitted, accepted);
                // l2-node 0.149.0 (plan §6): persist the walk's position (or
                // its finished high-water mark) — one put per applied page.
                if let Some(seed) = pending.resume.as_ref() {
                    self.persist_private_channel_sync_resume(&wallet, channel_id, &peer, &session, &step, &response, seed);
                }
                if matches!(step, private_channel_sync::NextStep::Finish { complete: false, .. })
                    && (response.has_more || response.meta_phase)
                {
                    warn!(
                        peer = %peer, %wallet, channel_id,
                        meta_pages = session.meta_pages, chat_pages = session.chat_pages,
                        consecutive_unproductive_pages = session.consecutive_unproductive_pages,
                        "private-channel-sync: hit a session backstop or a non-advancing/out-of-phase page; stopping"
                    );
                }
                let follow_up: Option<(
                    Option<private_channel_sync::PrivateChannelSyncCursor>,
                    Option<crate::network::reconcile::MetaCursor>,
                    bool,
                )> = match step {
                    private_channel_sync::NextStep::MetaPage(c) => Some((None, Some(c), false)),
                    // A catch-up enters chat at its seeded chat cursor
                    // (`None` for an ordinary walk: the first chat page).
                    private_channel_sync::NextStep::StartChat => Some(session.request_cursors()),
                    private_channel_sync::NextStep::ChatPage(c) => Some((Some(c), None, true)),
                    private_channel_sync::NextStep::Finish { complete, in_sync } => {
                        // Attempt throttle outcome (l2-node 0.141.0).
                        // COMPLETE → forget the key (the persisted marker
                        // and `channel_catchup_interval_hours` take over);
                        // IN_SYNC (verified nothing new — a throttle state
                        // only, NEVER written to the completion CF) →
                        // recheck after `in_sync_recheck_minutes`; new
                        // content but an early stop → retry in 30 s;
                        // anything else keeps the backoff set at dispatch.
                        let throttle_key = (wallet.clone(), channel_id);
                        let now_instant = Instant::now();
                        let finished_naturally = private_channel_sync::finished_naturally(&response);
                        if complete {
                            self.private_channel_sync_throttle.on_complete(&throttle_key);
                        } else if in_sync {
                            self.private_channel_sync_throttle.on_in_sync(
                                throttle_key,
                                now_instant,
                                budget::random_jitter(),
                            );
                            self.counters.inc_private_sync_in_sync_outcomes();
                            debug!(%wallet, channel_id, verified_dups = session.verified_dups, "private-channel-sync: verified in sync (nothing new); rechecking later");
                        } else if session.accepted_total > pending.accepted_base {
                            // THIS session admitted something new (the
                            // walk's carried-over count does not count).
                            self.private_channel_sync_throttle
                                .on_accepted_incomplete(throttle_key, now_instant);
                        }
                        if !finished_naturally {
                            // A same-peer continuation that ended early: a
                            // stall unless its cursors moved (round 2).
                            self.note_private_channel_sync_stall(&pending, &session);
                        }
                        // Completion only after BOTH phases ended and the
                        // session admitted at least one genuinely NEW,
                        // signature-verified envelope (`Accepted`, never
                        // merely `Duplicate`) — same hardened gate as
                        // `handle_reconcile_event` (an all-replayed
                        // response must not count as "nothing more").
                        if complete {
                            let now_secs = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            if let Err(e) = self
                                .storage
                                .mark_private_channel_sync_complete(&wallet, channel_id, now_secs)
                            {
                                warn!(%wallet, channel_id, error = %e, "private-channel-sync: failed to persist sync completion");
                            }
                        }
                        None
                    }
                };
                if let Some((cursor, meta_cursor, meta_done)) = follow_up {
                    let network = self.topics.network_id().to_string();
                    let max_age_secs = if self.private_channel_sync_config.max_age_days == 0 {
                        u64::MAX
                    } else {
                        self.private_channel_sync_config.max_age_days.saturating_mul(24 * 3600)
                    };
                    let claim = self.private_channel_sync_wallet_claims.get(&wallet).cloned();
                    let next_req = private_channel_sync::sign_request(
                        &self.signing_key,
                        &network,
                        &peer.to_string(),
                        &wallet,
                        channel_id,
                        now_ms(),
                        max_age_secs,
                        cursor,
                        claim,
                    );
                    let next_req = private_channel_sync::PrivateChannelSyncRequest {
                        meta_paging: true,
                        meta_cursor,
                        meta_done,
                        ..next_req
                    };
                    let next_id = self
                        .swarm
                        .behaviour_mut()
                        .private_channel_sync
                        .send_request(&peer, next_req);
                    self.pending_private_channel_sync_requests.insert(
                        next_id,
                        PrivateChannelSyncPending {
                            peer_id: peer,
                            wallet,
                            channel_id,
                            session,
                            accepted_base: pending.accepted_base,
                            resume: pending.resume,
                            same_peer_resume: pending.same_peer_resume,
                        },
                    );
                    // l2-node 0.149.0: the page may have changed membership.
                    // The continuation is registered above, so the session
                    // still counts as in flight and this can only
                    // re-subscribe; an unsubscribe waits for the release.
                    self.reconcile_channel_lifecycle(channel_id);
                    return;
                }
                self.release_private_channel_sync_trigger_if_no_siblings(&wallet, channel_id);
            }
            Event::OutboundFailure { peer, request_id, error, .. } => {
                if let Some(p) = self.pending_private_channel_sync_requests.remove(&request_id) {
                    debug!(peer = %peer, wallet = %p.wallet, channel_id = p.channel_id, error = ?error, "private-channel-sync: outbound failed; siblings may succeed");
                    self.note_private_channel_sync_stall(&p, &p.session);
                    self.release_private_channel_sync_trigger_if_no_siblings(&p.wallet, p.channel_id);
                }
            }
            _ => {}
        }
    }

    /// Periodic retry sweep for private-channel-history backfill (closes
    /// the F2 backfill gap, l2-node 0.138.0+). `maybe_trigger_private_
    /// channel_sync` only fires from `federate_channel`, which for most
    /// already-federated channels runs exactly once — at federation time.
    /// Without this sweep, a channel whose one attempt gave up (no
    /// candidate peers, an uninformative response, a page/unproductive-
    /// page backstop) has no way to ever retry short of re-federating.
    /// Mirrors `retry_incomplete_channel_backfills`'s shape exactly, but
    /// walks `LOCAL_CHANNEL_FED` (already keyed `(wallet, channel_id)` —
    /// precisely the candidate set this sweep needs) instead of
    /// `CHANNELS`, with its own rotating cursor so it survives restarts
    /// independently of the public-channel sweep's progress.
    fn retry_incomplete_private_channel_syncs(&mut self) {
        if !self.private_channel_sync_config.enabled {
            return;
        }
        let cursor_key = crate::storage::schema::state_keys::PRIVATE_CHANNEL_SYNC_RETRY_CURSOR;
        let start_key = self
            .storage
            .get_cf(crate::storage::schema::cf::NODE_STATE, cursor_key)
            .ok()
            .flatten()
            .unwrap_or_default();
        let batch = self.private_channel_sync_config.catchup_batch_size.max(1);
        let entries = match self.storage.prefix_iter_cf_after(
            crate::storage::schema::cf::LOCAL_CHANNEL_FED,
            &start_key,
            &[],
            batch,
        ) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "private-channel-sync retry sweep: LOCAL_CHANNEL_FED iteration failed");
                return;
            }
        };
        let hit_end = entries.len() < batch;
        let mut last_key: Option<Vec<u8>> = None;
        // One subscriber snapshot per sweep tick (only built if a
        // non-federated pair needs it — never here in practice).
        let mut subscribers: RemoteSubscriberCache = None;
        for (key, _) in &entries {
            // Key: wallet bytes ++ 0xFF ++ channel_id_be8. Wallet
            // addresses are bech32 (ASCII, never contains 0xFF), so the
            // first 0xFF byte unambiguously splits the two fields.
            if let Some(sep) = key.iter().position(|&b| b == 0xFF) {
                if key.len() == sep + 1 + 8 {
                    if let (Ok(wallet), Ok(channel_id_bytes)) = (
                        std::str::from_utf8(&key[..sep]),
                        <[u8; 8]>::try_from(&key[sep + 1..]),
                    ) {
                        let channel_id = u64::from_be_bytes(channel_id_bytes);
                        self.maybe_trigger_private_channel_sync_with(channel_id, wallet, None, false, &mut subscribers);
                    }
                }
            }
            last_key = Some(key.clone());
        }
        let next_cursor = if hit_end {
            Vec::new()
        } else {
            last_key.unwrap_or_default()
        };
        if let Err(e) = self.storage.put_cf(
            crate::storage::schema::cf::NODE_STATE,
            cursor_key,
            &next_cursor,
        ) {
            warn!(error = %e, "private-channel-sync retry sweep: failed to persist cursor");
        }
    }

    /// Periodic retry sweep for private-channel-sync pairs recorded only in
    /// `LOCAL_CHANNEL_HOMES` (l2-node 0.150.0, Phase E). Walks the
    /// `LOCAL_CHANNEL_HOMES_BY_WALLET` index `catchup_batch_size` keys per
    /// tick from its own rotating cursor
    /// (`PRIVATE_CHANNEL_SYNC_HOMES_RETRY_CURSOR`). Per key, cheapest check
    /// first: (1) a fresh cached claim for the wallet in memory — without
    /// one nothing can be sent, so the key is skipped with no storage read;
    /// (2) a `LOCAL_CHANNEL_FED` row (same key bytes) means the FED sweep
    /// already covers the pair; (3) the HOMES row must exist (the index is
    /// only a candidate set); then the normal throttled trigger.
    fn retry_incomplete_private_channel_syncs_homes(&mut self) {
        use crate::storage::schema::{cf, state_keys};
        if !self.private_channel_sync_config.enabled {
            return;
        }
        let cursor_key = state_keys::PRIVATE_CHANNEL_SYNC_HOMES_RETRY_CURSOR;
        let start_key = self
            .storage
            .get_cf(cf::NODE_STATE, cursor_key)
            .ok()
            .flatten()
            .unwrap_or_default();
        let batch = self.private_channel_sync_config.catchup_batch_size.max(1);
        let entries = match self.storage.prefix_iter_cf_after(
            cf::LOCAL_CHANNEL_HOMES_BY_WALLET,
            &start_key,
            &[],
            batch,
        ) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "private-channel-sync HOMES retry sweep: index iteration failed");
                return;
            }
        };
        let hit_end = entries.len() < batch;
        let max_age = private_channel_sync::WALLET_AUTH_MAX_AGE_SECS.saturating_mul(1000);
        let now = now_ms();
        let mut last_key: Option<Vec<u8>> = None;
        // One subscriber snapshot per sweep tick.
        let mut subscribers: RemoteSubscriberCache = None;
        for (key, _) in &entries {
            last_key = Some(key.clone());
            let Some((wallet_bytes, channel_id)) = crate::storage::schema::decode_wallet_channel_key(key) else {
                continue;
            };
            let Ok(wallet) = std::str::from_utf8(wallet_bytes) else { continue };
            // (1) In memory only: a cached claim inside its freshness window
            // (full usability incl. device revocation is checked inside the
            // trigger).
            let has_claim = self
                .private_channel_sync_wallet_claims
                .get(wallet)
                .is_some_and(|c| now.abs_diff(c.timestamp) <= max_age);
            if !has_claim {
                continue;
            }
            self.counters.add_private_sync_homes_pairs_evaluated(1);
            // (2) Covered by the FED sweep (identical key bytes).
            if !matches!(self.storage.exists_cf(cf::LOCAL_CHANNEL_FED, key), Ok(false)) {
                continue;
            }
            // (3) The index is a candidate set: verify the HOMES row.
            let home_key = crate::storage::schema::encode_local_channel_home_key(channel_id, wallet);
            if !matches!(self.storage.exists_cf(cf::LOCAL_CHANNEL_HOMES, &home_key), Ok(true)) {
                continue;
            }
            self.maybe_trigger_private_channel_sync_with(channel_id, wallet, None, false, &mut subscribers);
        }
        let next_cursor = if hit_end {
            Vec::new()
        } else {
            last_key.unwrap_or_default()
        };
        // Skip the write when nothing moved (e.g. an empty index).
        if next_cursor != start_key {
            if let Err(e) = self.storage.put_cf(cf::NODE_STATE, cursor_key, &next_cursor) {
                warn!(error = %e, "private-channel-sync HOMES retry sweep: failed to persist cursor");
            }
        }
    }

    /// True if the channel exists (chain-scanned) but we've applied NO L2
    /// metadata envelope for it — i.e. there is no `CHANNEL_META_MSGS` row for
    /// the channel. Such a channel is a pure on-chain skeleton (slug/creator
    /// only) and needs a metadata pull even if it already has chat.
    ///
    /// We key on "no metadata envelope applied" rather than "display_name is
    /// null" so a channel legitimately created WITHOUT a name (its
    /// `ChannelCreate` was applied → it has a `CHANNEL_META_MSGS` row) is NOT
    /// treated as a skeleton, and doesn't trigger a redundant reconcile every
    /// session.
    fn channel_is_skeleton(&self, channel_id: u64) -> bool {
        let key = channel_id.to_be_bytes();
        let exists = self
            .storage
            .exists_cf(crate::storage::schema::cf::CHANNELS, &key)
            .unwrap_or(false);
        if !exists {
            return false;
        }
        // No CHANNEL_META_MSGS row for this channel → no ChannelCreate/Update
        // has been applied here → skeleton. On a read error, default to
        // "has metadata" (not skeleton) so we never spuriously re-trigger.
        let has_meta = self
            .storage
            .prefix_iter_cf(crate::storage::schema::cf::CHANNEL_META_MSGS, &key, 1)
            .map(|rows| !rows.is_empty())
            .unwrap_or(true);
        !has_meta
    }

    fn maybe_trigger_backfill(&mut self, channel_id: u64) {
        if !self.backfill_config.enabled {
            return;
        }
        // Code-audit follow-up (2026-09-30): `reconcile::build_response`
        // refuses every private-channel request unconditionally
        // (`server_capped`, no envelopes — there's no authenticated-
        // membership proof in this wire protocol). A private channel can
        // therefore never reach natural completion over this path, so
        // without this check it would be retried every periodic-sweep
        // tick forever, purely wasted fanout traffic. Skip entirely —
        // this never touches `reconcile_triggered`, so it also never
        // needs releasing.
        if reconcile::is_private_channel(&self.storage, channel_id) {
            return;
        }
        if !self.reconcile_triggered.insert(channel_id) {
            // Already in flight (or due-but-not-yet-resolved) this
            // session — don't pile another request on top of it.
            return;
        }

        // P-3b: also backfill a channel that is a SKELETON — chain-scanned (has
        // the on-chain slug/creator) but missing its L2 metadata (display_name
        // null), even if it already has chat. The reconcile rides the
        // ChannelCreate/Update envelopes on its first page, so this is how an
        // existing chain-discovered channel finally gets its name/logo/members.
        let is_skeleton = self.channel_is_skeleton(channel_id);

        // Completeness gate (rewritten 2026-09-30 — see
        // `storage::schema::cf::CHANNEL_BACKFILL_STATE`'s doc comment for the
        // any-row-proxy bug this replaces). `None` means no reconciliation
        // session has ever reached natural completion for this channel —
        // always due, regardless of how much (possibly gossip-delivered,
        // possibly still-partial) local history already exists. Once
        // completed, due again only after `channel_catchup_interval_hours`.
        let completed_at = self.storage.channel_backfill_completed_at(channel_id);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let due = channel_backfill_due(
            completed_at,
            now,
            self.backfill_config.channel_catchup_interval_hours,
        );
        let need_backfill = is_skeleton || due;
        // l2-node 0.141.0: … AND the attempt throttle allows it (backoff
        // after a dispatch, a recheck after a verified in-sync comparison;
        // no entry == due, so a fresh process or a newly discovered channel
        // is always attempted). Before this, a channel that never reached
        // COMPLETE (every in-sync channel: all-`Duplicate` answers never
        // complete) was re-walked on every 30 s sweep rotation.
        let now_instant = Instant::now();
        if !need_backfill || !self.reconcile_throttle.ready(&channel_id, now_instant) {
            // Not due — release immediately so a future resubscribe
            // (or the periodic retry sweep) re-evaluates fresh rather
            // than being blocked by this session's own dedup entry.
            self.reconcile_triggered.remove(&channel_id);
            return;
        }

        // Candidate selection: GossipSub mesh peers for this
        // channel's topic; fall back to ALL connected peers if the
        // mesh is sparse (cold-start case where the channel topic
        // has not yet propagated).
        let topic = libp2p::gossipsub::IdentTopic::new(gossip::channel_topic(
            self.topics.network_id(),
            channel_id,
        ));
        let topic_hash = topic.hash();
        let mut candidates: Vec<PeerId> = self
            .swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&topic_hash)
            .copied()
            .collect();
        if candidates.len() < self.backfill_config.fanout {
            // Augment with any connected peer that announced the
            // protocol (or just any connected peer — request-response
            // negotiation will refuse non-supporters cleanly).
            for p in self.swarm.connected_peers() {
                if !candidates.contains(p) {
                    candidates.push(*p);
                }
                if candidates.len() >= self.backfill_config.fanout * 2 {
                    break;
                }
            }
        }
        if candidates.is_empty() {
            debug!(
                channel_id,
                "backfill: no candidate peers; cold-start will retry on next subscribe"
            );
            // Allow a future re-trigger.
            self.reconcile_triggered.remove(&channel_id);
            return;
        }

        // l2-node 0.137.0: deprioritize (never exclude) peers currently
        // flagged stale — see `PeerReconcileHealth`'s doc comment. Split
        // BEFORE shuffling so a stale peer only fills the fanout when
        // there aren't enough healthy candidates to do it without them.
        use rand::seq::SliceRandom;
        let stale_threshold = self.backfill_config.stale_peer_threshold;
        let (mut healthy, mut stale): (Vec<PeerId>, Vec<PeerId>) = candidates
            .into_iter()
            .partition(|p| {
                !is_peer_stale(
                    self.peer_reconcile_health
                        .get(p)
                        .map(|h| h.consecutive_losses)
                        .unwrap_or(0),
                    stale_threshold,
                )
            });
        healthy.shuffle(&mut rand::thread_rng());
        stale.shuffle(&mut rand::thread_rng());
        healthy.truncate(self.backfill_config.fanout);
        let mut candidates = healthy;
        candidates.extend(
            stale
                .iter()
                .copied()
                .take(self.backfill_config.fanout.saturating_sub(candidates.len())),
        );

        // l2-node 0.137.0, security-audit finding (2026-09-30, round 1):
        // refuse to open another comparison past a fixed concurrency
        // cap — see `MAX_CONCURRENT_RECONCILE_COMPARISONS`'s doc comment
        // for why an uncapped map here is a real unbounded-memory risk,
        // not merely theoretical (the startup subscribe loop in
        // `src/node.rs` can call this for up to 100,000 channels with no
        // throttling between iterations). Checked BEFORE the reprobe
        // block and before dispatching any requests (code-audit finding,
        // 2026-09-30, round 2: checking this AFTER stamping a reprobe
        // candidate's `last_probed_at` would burn that peer's recovery
        // window even though no request was ever actually sent to it).
        if self.pending_reconcile_comparisons.len() >= MAX_CONCURRENT_RECONCILE_COMPARISONS {
            debug!(
                channel_id,
                "backfill: too many concurrent reconcile comparisons in flight; \
                 deferring to a later periodic-sweep tick"
            );
            self.reconcile_triggered.remove(&channel_id);
            return;
        }

        // Periodic re-probe (l2-node 0.137.0, `[backfill]
        // stale_peer_reprobe_hours`): give ONE peer that's still flagged
        // stale — and wasn't already pulled in as fanout filler above —
        // an extra, above-`fanout` chance to requalify, so a genuinely
        // recovered peer isn't deprioritized forever just because there
        // are always enough healthy siblings around. Resetting
        // `consecutive_losses` on a competitive showing (`record_
        // reconcile_peer_result`) is what actually "unflags" it — this
        // just makes sure that showing happens at all.
        if self.backfill_config.stale_peer_reprobe_hours > 0 {
            let reprobe_interval = std::time::Duration::from_secs(
                self.backfill_config.stale_peer_reprobe_hours.saturating_mul(3600),
            );
            let now_instant = Instant::now();
            if let Some(&candidate) = stale.iter().find(|p| !candidates.contains(p)) {
                let due = self
                    .peer_reconcile_health
                    .get(&candidate)
                    .and_then(|h| h.last_probed_at)
                    .map(|last| now_instant.duration_since(last) >= reprobe_interval)
                    .unwrap_or(true);
                if due {
                    candidates.push(candidate);
                    // `candidate` is only ever drawn from `stale`, which
                    // requires an existing `peer_reconcile_health` entry
                    // (see `is_peer_stale`'s use above) — this never
                    // inserts a new one, so the Sybil soft cap can't be
                    // hit here; `touch_peer_reconcile_health` is still
                    // used for consistency with every other write site.
                    if let Some(health) =
                        self.touch_peer_reconcile_health(candidate, now_instant)
                    {
                        health.last_probed_at = Some(now_instant);
                    }
                }
            }
        }

        let max_age_secs = if self.backfill_config.max_age_days == u64::MAX {
            u64::MAX
        } else {
            self.backfill_config
                .max_age_days
                .saturating_mul(24 * 3600)
        };
        let request = reconcile::ReconcileRequest {
            channel_id,
            max_age_secs,
            cursor: None,
            fingerprint: Vec::new(),
            epoch_root_known: None,
            round: 0,
            meta_cursor: None,
            revision: reconcile::RECONCILE_REVISION,
        };

        info!(
            channel_id,
            fanout = candidates.len(),
            max_age_days = self.backfill_config.max_age_days,
            "backfill: triggering channel-history reconciliation"
        );

        // l2-node 0.141.0: stamp the attempt HERE — after every early
        // return above (not due, no candidates, the comparison cap), right
        // before the requests are actually sent.
        self.reconcile_throttle
            .on_dispatch(channel_id, now_instant, budget::random_jitter());
        self.counters.inc_reconcile_attempts_dispatched();

        // l2-node 0.137.0: every fresh trigger opens a comparison window
        // instead of racing to the first informative response — see
        // `ReconcileComparison`'s doc comment.
        let mut outstanding = HashSet::new();
        for peer in candidates {
            let id = self
                .swarm
                .behaviour_mut()
                .reconcile
                .send_request(&peer, request.clone());
            self.pending_reconcile_requests.insert(
                id,
                ReconcilePending {
                    peer_id: peer,
                    channel_id,
                    pages_fetched: 0,
                    consecutive_unproductive_pages: 0,
                    total_accepted: 0,
                    meta: ReconcileMetaState::default(),
                },
            );
            outstanding.insert(id);
        }
        self.pending_reconcile_comparisons.insert(
            channel_id,
            ReconcileComparison {
                outstanding,
                candidates: Vec::new(),
                deadline: Instant::now() + RECONCILE_COMPARE_WINDOW,
                any_capped: false,
            },
        );
    }

    /// Release `channel_id`'s `reconcile_triggered` dedup entry, but only
    /// once no OTHER pending reconcile request still references it — a
    /// still-pending sibling (race-fanout candidate, or a later page of an
    /// ongoing session) might yet complete the channel, and releasing the
    /// dedup entry while one is still in flight would let the periodic
    /// retry sweep fire a redundant extra request on top of it.
    fn release_reconcile_trigger_if_no_siblings(&mut self, channel_id: u64) {
        let still_pending = self
            .pending_reconcile_requests
            .values()
            .any(|p| p.channel_id == channel_id);
        if !still_pending {
            self.reconcile_triggered.remove(&channel_id);
        }
    }

    /// Periodic retry sweep for channel-history backfill (l2-node 0.136.0).
    ///
    /// `maybe_trigger_backfill` only fires from `subscribe_channel`, which
    /// for most existing channels runs exactly once — at startup. Without
    /// this sweep, a channel whose one attempt gave up (no candidate peers,
    /// an uninformative response, a page/unproductive-page backstop) has no
    /// way to ever retry short of a process restart. Mirrors
    /// `maybe_trigger_news_backfill`'s shape (retry on `bootstrap_interval`
    /// until due, then back off) but per-channel and persisted, since
    /// unlike the single global news feed there can be many channels and
    /// this must survive restarts.
    ///
    /// Walks a bounded, rotating batch (`catchup_batch_size`) of the
    /// `CHANNELS` table per call via a persisted cursor
    /// (`CHANNEL_BACKFILL_RETRY_CURSOR`) so cost stays flat regardless of
    /// total channel count — same reasoning as `ChainScanner::
    /// sweep_channel_verification`'s round-robin lane. Each examined
    /// channel goes through the exact same due-check `maybe_trigger_backfill`
    /// already applies, so an already-complete-and-not-yet-due, or
    /// already-in-flight, channel is just a cheap point read.
    ///
    /// Round-3 security-audit correction: a channel that's genuinely
    /// fully synced but whose completion signal keeps failing to persist
    /// (every reconcile session comes back all-`Duplicate` — see
    /// `ReconcilePending::total_accepted`'s doc comment) is NOT a cheap
    /// point read once triggered — v0.47.0 always bulk-sends, so it pages
    /// through and deserializes real envelope batches every retry cycle.
    /// Bounded, not DoS-class, but a real recurring cost until spec-14
    /// fingerprinting lands. l2-node 0.141.0 bounds how OFTEN it is paid:
    /// `maybe_trigger_backfill` also requires `reconcile_throttle` to be
    /// ready (exponential backoff after each dispatch, an
    /// `in_sync_recheck_minutes` recheck after a verified in-sync
    /// comparison), so such a channel is re-walked about hourly instead of
    /// on every rotation.
    fn retry_incomplete_channel_backfills(&mut self) {
        if !self.backfill_config.enabled {
            return;
        }
        let cursor_key = crate::storage::schema::state_keys::CHANNEL_BACKFILL_RETRY_CURSOR;
        let start_key = self
            .storage
            .get_cf(crate::storage::schema::cf::NODE_STATE, cursor_key)
            .ok()
            .flatten()
            .unwrap_or_default();
        let batch = self.backfill_config.catchup_batch_size.max(1);
        let entries = match self.storage.prefix_iter_cf_after(
            crate::storage::schema::cf::CHANNELS,
            &start_key,
            &[],
            batch,
        ) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "backfill retry sweep: CHANNELS iteration failed");
                return;
            }
        };
        let hit_end = entries.len() < batch;
        let mut last_key: Option<Vec<u8>> = None;
        for (key, _) in &entries {
            if key.len() == 8 {
                let channel_id = u64::from_be_bytes(
                    <[u8; 8]>::try_from(key.as_slice()).expect("len checked"),
                );
                self.maybe_trigger_backfill(channel_id);
            }
            last_key = Some(key.clone());
        }
        // Wrap to the start once the batch runs out of rows; otherwise
        // resume strictly after the last key we just examined.
        let next_cursor = if hit_end {
            Vec::new()
        } else {
            last_key.unwrap_or_default()
        };
        if let Err(e) = self.storage.put_cf(
            crate::storage::schema::cf::NODE_STATE,
            cursor_key,
            &next_cursor,
        ) {
            warn!(error = %e, "backfill retry sweep: failed to persist cursor");
        }
    }

    /// Periodic prune (30 s tick, l2-node 0.141.0): drops responder-budget
    /// entries whose bucket is full again — never one still in debt, which
    /// would be a free refill — and throttle entries idle past their
    /// `next_due + retry_backoff_max` (no entry == due).
    fn prune_backfill_budgets(&mut self, now: Instant) {
        self.reconcile_limits.prune(now);
        self.sync_limits.prune(now);
        self.private_channel_sync_limits.prune(now);
        // l2-node 0.151.0: the news / dm / identity-sync responder budgets.
        self.news_sync_limits.prune(now);
        self.dm_sync_limits.prune(now);
        self.identity_sync_limits.prune(now);
        self.reconcile_throttle.prune(now);
        self.private_channel_sync_throttle.prune(now);
    }

    /// Count a responder refusal caused by the rolling budget (l2-node
    /// 0.141.0) — concurrency refusals are not budget refusals and are not
    /// counted. `reconcile` selects the public-reconcile vs the
    /// private-channel-sync counter; a full key map is also counted on its
    /// own (a flood indicator).
    fn count_budget_refusal(&self, refusal: budget::Refusal, reconcile: bool) {
        match refusal {
            budget::Refusal::Concurrency => return,
            budget::Refusal::MapFull => self.counters.inc_backfill_budget_map_full_refusals(),
            budget::Refusal::OverBudget => {}
        }
        if reconcile {
            self.counters.inc_reconcile_budget_refusals();
        } else {
            self.counters.inc_private_sync_budget_refusals();
        }
    }

    /// Count a news / dm / identity-sync responder refusal (l2-node
    /// 0.151.0). Only a full key map is counted (the shared flood
    /// indicator); per-protocol over-budget refusals are logged at debug.
    fn count_sync_budget_refusal(&self, refusal: budget::Refusal) {
        match refusal {
            budget::Refusal::MapFull => self.counters.inc_backfill_budget_map_full_refusals(),
            budget::Refusal::OverBudget => debug!("sync responder: peer over its rolling budget; answering server_capped"),
            budget::Refusal::Concurrency => {}
        }
    }

    /// Handle inbound + outbound reconcile request-response events.
    fn handle_reconcile_event(
        &mut self,
        event: libp2p::request_response::Event<
            reconcile::ReconcileRequest,
            reconcile::ReconcileResponse,
        >,
    ) {
        use libp2p::request_response::{Event, Message};
        match event {
            Event::Message {
                peer,
                message: Message::Request { request, channel, request_id: _ },
                connection_id: _,
            } => {
                // Server-side: rate-limit + rolling budget, then build +
                // respond. The Audit C2 work budget (`total_envelopes_cap`
                // burst, refilled at `total_envelopes_refill_per_hour`
                // since 0.141.0) is enforced through `try_acquire`; on
                // success the build is charged (`charge`) before the
                // response is queued, so the next paginated request from
                // the same peer sees the updated budget.
                let budget = self.reconcile_budget;
                let guard = match self.reconcile_limits.try_acquire(
                    peer,
                    request.channel_id,
                    self.backfill_config.server_max_concurrent_per_peer,
                    self.backfill_config.server_max_concurrent_per_channel,
                    &budget,
                    Instant::now(),
                ) {
                    Ok(g) => Some(g),
                    Err(refusal) => {
                        self.count_budget_refusal(refusal, true);
                        None
                    }
                };
                // Round 4: the build runs OFF the swarm event loop under a
                // node-wide build slot; a capped request (per-peer limits,
                // session budget, or no free build slot for a
                // session-starting page) is answered inline. A continuation
                // page (cursor present) waits briefly for a slot instead
                // (round-5 C-W1, `responder_build_slot`).
                let admitted = guard.and_then(|g| match self.responder_build_slot(request.is_continuation()) {
                    BuildSlot::Refuse => None,
                    slot => Some((g, slot)),
                });
                let Some((guard, slot)) = admitted else {
                    debug!(
                        peer = %peer,
                        channel_id = request.channel_id,
                        "reconcile: rate-limited, session-cap exhausted or no build slot; \
                         responding server_capped"
                    );
                    if let Err(e) = self
                        .swarm
                        .behaviour_mut()
                        .reconcile
                        .send_response(channel, reconcile::capped_response(&request))
                    {
                        warn!(
                            peer = %peer,
                            channel_id = request.channel_id,
                            error = ?e,
                            "reconcile: send_response failed"
                        );
                    }
                    return;
                };
                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let storage = self.storage.clone();
                let limits = Arc::clone(&self.reconcile_limits);
                let max_envelopes = self.backfill_config.max_envelopes_per_response;
                let tx = self.deferred_response_tx.clone();
                // `Ok` = build slot; `Err` = a continuation timed out waiting
                // (the waiter slot rides along with the capped response).
                let run = move |slot: Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::OwnedSemaphorePermit>| {
                    let build_permit = match slot {
                        Ok(p) => p,
                        Err(waiter) => {
                            let _ = tx.send(DeferredResponse::Reconcile {
                                peer,
                                channel_id: request.channel_id,
                                channel,
                                response: reconcile::capped_response(&request),
                                _guard: guard,
                                _build_permit: waiter,
                            });
                            return;
                        }
                    };
                    tokio::task::spawn_blocking(move || {
                        let (response, work) =
                            reconcile::build_response_metered(&storage, &request, max_envelopes, now_unix);
                        // Audit C2 + round 4: charge the (peer, channel)
                        // session budget for scan work as well as envelopes
                        // sent (minimum 1 — empty pages, including the
                        // private-channel refusal, are no longer free).
                        limits.charge(
                            peer,
                            request.channel_id,
                            reconcile::budget_charge(response.envelopes.len(), work),
                            &budget,
                            Instant::now(),
                        );
                        let _ = tx.send(DeferredResponse::Reconcile {
                            peer,
                            channel_id: request.channel_id,
                            channel,
                            response,
                            _guard: guard,
                            _build_permit: build_permit,
                        });
                    });
                };
                match slot {
                    BuildSlot::Now(p) => run(Ok(p)),
                    BuildSlot::Wait(w) => {
                        let permits = self.responder_build_permits.clone();
                        tokio::spawn(async move { run(wait_for_build_slot(permits, w).await) });
                    }
                    BuildSlot::Refuse => {}
                }
            }
            Event::Message {
                peer,
                message: Message::Response { request_id, response },
                connection_id: _,
            } => {
                let Some(pending) = self.pending_reconcile_requests.remove(&request_id)
                else {
                    debug!(
                        peer = %peer,
                        ?request_id,
                        "reconcile: response for unknown request_id (race winner already served)"
                    );
                    return;
                };
                // l2-node 0.137.0: a fresh (cursor: None) fanout's first
                // page is compared across every candidate before any of
                // them is trusted — see `ReconcileComparison`'s doc
                // comment for why (a stale-but-fast peer used to win
                // purely by answering first). A continuation page never
                // has an open comparison for its channel (the winner is
                // already committed by then), so this only ever routes
                // first pages.
                if self.pending_reconcile_comparisons.contains_key(&pending.channel_id) {
                    self.record_reconcile_comparison_response(
                        pending.channel_id,
                        request_id,
                        peer,
                        response,
                    );
                    return;
                }
                self.apply_reconcile_response(pending, peer, response, true);
            }
            Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                if let Some(pending) =
                    self.pending_reconcile_requests.remove(&request_id)
                {
                    debug!(
                        peer = %peer,
                        channel_id = pending.channel_id,
                        error = ?error,
                        "reconcile: outbound failed; siblings may still succeed"
                    );
                    // l2-node 0.137.0: route into an open comparison
                    // window exactly like the Response arm does — see
                    // that arm's comment.
                    if self.pending_reconcile_comparisons.contains_key(&pending.channel_id) {
                        self.record_reconcile_comparison_failure(pending.channel_id, request_id);
                        return;
                    }
                    // G7 (l2-node 0.152.0): an in-session metadata walk
                    // that fails is "accepted but incomplete" (its chat
                    // phase admitted new content) — retry soon.
                    if let Some(walk) = pending.meta.walk.as_ref() {
                        // W2: the next walk with this peer continues here.
                        self.remember_reconcile_meta_resume(pending.channel_id, pending.peer_id, walk.last_cursor.clone());
                        if !walk.followup {
                            self.note_reconcile_accepted_incomplete(pending.channel_id, pending.total_accepted);
                        }
                    }
                    // Only give up once every sibling for this channel has
                    // failed — otherwise a still-pending sibling might
                    // yet complete it, and releasing the dedup entry here
                    // would let the periodic sweep fire a redundant extra
                    // request on top of it.
                    self.release_reconcile_trigger_if_no_siblings(pending.channel_id);
                }
            }
            Event::InboundFailure { peer, error, .. } => {
                debug!(
                    peer = %peer,
                    error = ?error,
                    "reconcile: inbound request handling failed"
                );
            }
            Event::ResponseSent { .. } => {
                // Successfully sent — nothing to do.
            }
        }
    }

    /// Records one candidate's answer toward an open first-page
    /// comparison (l2-node 0.137.0) instead of acting on it immediately.
    /// Finalizes the comparison as soon as every dispatched request has
    /// resolved one way or another; `reconcile_compare_interval` handles
    /// the case where one candidate never resolves in time.
    fn record_reconcile_comparison_response(
        &mut self,
        channel_id: u64,
        request_id: libp2p::request_response::OutboundRequestId,
        peer: PeerId,
        response: reconcile::ReconcileResponse,
    ) {
        let Some(cmp) = self.pending_reconcile_comparisons.get_mut(&channel_id) else {
            // Defensive: shouldn't happen, the caller just checked
            // `contains_key`, but nothing here can race it (single-
            // threaded event loop) — return rather than panic.
            return;
        };
        // Code-audit finding (2026-09-30, round 1), defense-in-depth:
        // only record a candidate for a request_id this comparison
        // actually dispatched. Every current path already guarantees
        // this (a channel's comparison can't be replaced while a prior
        // one's requests are still unresolved — `reconcile_triggered`'s
        // dedup guard depends on `pending_reconcile_requests` being
        // fully drained first), but that invariant is cross-cutting and
        // not locally enforced here — cheap to check directly rather
        // than rely on it holding forever.
        if !cmp.outstanding.remove(&request_id) {
            debug!(
                peer = %peer,
                channel_id,
                ?request_id,
                "reconcile: response for a request_id this comparison never dispatched; ignoring"
            );
            return;
        }
        let informative =
            !response.server_capped && !(response.envelopes.is_empty() && !response.has_more);
        cmp.any_capped |= response.server_capped;
        if informative {
            cmp.candidates.push((peer, response));
        } else {
            debug!(
                peer = %peer,
                channel_id,
                "reconcile: comparison candidate answered uninformatively"
            );
        }
        if cmp.outstanding.is_empty() {
            self.finalize_reconcile_comparison(channel_id);
        }
    }

    /// `OutboundFailure` counterpart to `record_reconcile_comparison_response`
    /// — a failed candidate just leaves `outstanding`, contributing
    /// nothing to `candidates` (l2-node 0.137.0).
    fn record_reconcile_comparison_failure(
        &mut self,
        channel_id: u64,
        request_id: libp2p::request_response::OutboundRequestId,
    ) {
        let Some(cmp) = self.pending_reconcile_comparisons.get_mut(&channel_id) else {
            return;
        };
        if !cmp.outstanding.remove(&request_id) {
            return;
        }
        if cmp.outstanding.is_empty() {
            self.finalize_reconcile_comparison(channel_id);
        }
    }

    /// Called every `reconcile_compare_interval` tick (l2-node 0.137.0):
    /// finalizes any open comparison whose `deadline` has passed, even if
    /// not every candidate has answered — bounds one slow/dead
    /// candidate's worst-case delay without waiting for the protocol's
    /// full 45s request timeout. Collects expired keys first since
    /// `finalize_reconcile_comparison` mutates the same map.
    fn finalize_expired_reconcile_comparisons(&mut self) {
        if self.pending_reconcile_comparisons.is_empty() {
            return;
        }
        let now = Instant::now();
        let expired: Vec<u64> = self
            .pending_reconcile_comparisons
            .iter()
            .filter(|(_, cmp)| now >= cmp.deadline)
            .map(|(&channel_id, _)| channel_id)
            .collect();
        for channel_id in expired {
            debug!(channel_id, "reconcile: comparison window deadline reached; finalizing with whoever has answered so far");
            self.finalize_reconcile_comparison(channel_id);
        }
    }

    /// Resolves an open comparison window (l2-node 0.137.0): tries
    /// whichever candidates answered informatively, ranked by how much
    /// content they reported — each one fully verified through the same
    /// pipeline a direct (non-comparison) response would use — stopping
    /// at the first one that yields genuine (`RouteResult::Accepted`)
    /// progress.
    ///
    /// Trying candidates one at a time (rather than cancelling the
    /// "losers" up front by raw count alone) matters: a candidate that
    /// merely reported a bigger first page hasn't yet proven any of it
    /// verifies. Committing to it immediately — and giving up on genuinely
    /// better siblings — would just relocate the exact pre-emption bug
    /// this design exists to close, from "answers fastest wins" to
    /// "claims the biggest page wins."
    ///
    /// Round-1 security-audit finding (2026-09-30): the first version of
    /// this function updated `peer_reconcile_health` from the RAW,
    /// pre-verification reported counts before trying anyone — which let
    /// a single peer padding a huge garbage/duplicate-heavy count (the
    /// exact ghost-peer/attacker shape this whole feature exists to
    /// guard against) become the "leading" reference and drag every
    /// HONEST peer's staleness counter up, inverting the feature's own
    /// purpose. Fixed by scoring strictly from VERIFIED trial outcomes
    /// instead: a peer is only ever marked "behind" once it has actually
    /// been tried and failed to deliver anything real (`NoProgress`)
    /// AND a later trial in the SAME comparison proved real content
    /// existed (found a winner). Candidates never tried at all (ranked
    /// after the winner) get no update either way — there is no
    /// verified basis to judge them, and trying them just to find out
    /// would reintroduce the extra verification cost this design
    /// otherwise avoids. A comparison where nobody wins updates nobody's
    /// health at all — universal failure isn't evidence of any ONE
    /// peer being relatively behind.
    fn finalize_reconcile_comparison(&mut self, channel_id: u64) {
        let Some(cmp) = self.pending_reconcile_comparisons.remove(&channel_id) else {
            return;
        };
        // l2-node 0.141.0: IN_SYNC needs every dispatched candidate to have
        // answered BEFORE this finalize (not the deadline path with a
        // straggler still out) and none of them `server_capped`.
        let all_answered = cmp.outstanding.is_empty();
        let any_capped = cmp.any_capped;
        // Code-audit finding (2026-09-30, round 2): purge any still-
        // outstanding stragglers' `pending_reconcile_requests` entries
        // NOW, unconditionally, regardless of how this comparison
        // resolves below. This finalize can run via the deadline sweep
        // (`finalize_expired_reconcile_comparisons`) specifically while
        // `cmp.outstanding` is non-empty — every candidate that HAS
        // already answered already had its own entry removed the
        // moment its response/failure arrived (see the `Message::
        // Response`/`OutboundFailure` arms), so anything still left in
        // `pending_reconcile_requests` for this channel_id at this
        // point belongs ONLY to a genuine straggler, never to a
        // candidate this function is about to try. Purging only from
        // the "no winner" tail (the original, incomplete fix) missed
        // the other two exits below — when a straggler's real response
        // later arrived at an unknown request_id, it fell through to
        // the DIRECT single-peer path, could pass `newly_accepted > 0`
        // for an unrelated reason, and its sibling-cancellation retain
        // would then delete the ACTUAL winner's just-inserted
        // continuation-page entry (inserted below, after this point) —
        // silently orphaning that continuation forever and leaving
        // `reconcile_triggered` stuck until process restart. Running
        // the purge here, before the winner's own continuation entry
        // can even be created, makes that ordering impossible.
        self.pending_reconcile_requests
            .retain(|_, p| p.channel_id != channel_id);
        if cmp.candidates.is_empty() {
            debug!(channel_id, "reconcile: comparison resolved with no informative candidates");
            self.release_reconcile_trigger_if_no_siblings(channel_id);
            return;
        }
        let order = rank_reconcile_candidates_by_size(&cmp.candidates);
        info!(
            channel_id,
            candidates = cmp.candidates.len(),
            "reconcile: comparison resolved; trying candidates in ranked order"
        );
        let mut slots: Vec<Option<(PeerId, reconcile::ReconcileResponse)>> =
            cmp.candidates.into_iter().map(Some).collect();
        // (peer, had_real_progress) for every candidate actually tried,
        // in try order — fed to `split_reconcile_trial_results` once a
        // winner is found (or exhausted with none).
        let mut trials: Vec<(PeerId, bool)> = Vec::new();
        // (peer, verified_in_sync) per tried candidate (l2-node 0.141.0) —
        // the in-sync evidence for `comparison_in_sync`; never used for
        // peer health.
        let mut in_sync_trials: Vec<(PeerId, bool)> = Vec::new();
        // G7 (l2-node 0.152.0): tried candidates that may serve a metadata
        // follow-up walk, in try (rank) order.
        let mut meta_followup_peers: Vec<(PeerId, Option<reconcile::MetaCursor>)> = Vec::new();
        for idx in order {
            let (peer, response) = slots[idx].take().expect("each index visited exactly once");
            // Where this candidate's first-page metadata prefix ended (N2).
            let trial_prefix_end = response.meta_next_cursor.clone();
            let trial_pending = ReconcilePending {
                peer_id: peer,
                channel_id,
                pages_fetched: 0,
                consecutive_unproductive_pages: 0,
                total_accepted: 0,
                meta: ReconcileMetaState::default(),
            };
            match self.apply_reconcile_response(trial_pending, peer, response, false) {
                ReconcileApplyOutcome::Handled => {
                    trials.push((peer, true));
                    let (competitive, behind) = split_reconcile_trial_results(&trials);
                    for p in competitive {
                        self.record_reconcile_peer_result(p, true);
                    }
                    for p in behind {
                        self.record_reconcile_peer_result(p, false);
                    }
                    return;
                }
                ReconcileApplyOutcome::NoProgress { verified_in_sync, meta_followup } => {
                    trials.push((peer, false));
                    in_sync_trials.push((peer, verified_in_sync));
                    if meta_followup {
                        meta_followup_peers.push((peer, trial_prefix_end));
                    }
                    continue;
                }
            }
        }
        // Every informative candidate was tried and none yielded real
        // progress — no winner to compare anyone against, so staleness
        // tracking stays untouched this round (see the doc comment
        // above). Give up on this trigger the same way the direct
        // path's zero-progress branch does, just once for the whole
        // comparison rather than once per candidate (see
        // `ReconcileApplyOutcome::NoProgress`'s doc comment for why the
        // trials themselves don't release this). Stragglers were
        // already purged unconditionally above.
        //
        // l2-node 0.141.0: if every tried candidate proved a verified
        // in-sync first page (`comparison_in_sync`), move the attempt
        // throttle to its in-sync recheck instead of the dispatch backoff.
        // A THROTTLE STATE ONLY: no completion marker, no peer-health
        // update (0.137 semantics: no winner, no health change).
        let threshold = self.backfill_config.stale_peer_threshold;
        let in_sync = comparison_in_sync(all_answered, any_capped, &in_sync_trials, |p| {
            is_peer_stale(
                self.peer_reconcile_health.get(p).map(|h| h.consecutive_losses).unwrap_or(0),
                threshold,
            )
        });
        if in_sync {
            self.reconcile_throttle
                .on_in_sync(channel_id, Instant::now(), budget::random_jitter());
            self.counters.inc_reconcile_in_sync_outcomes();
            debug!(channel_id, candidates = in_sync_trials.len(), "reconcile: comparison verified in sync (nothing new); rechecking later");
        }
        // G7 (l2-node 0.152.0): our chat matches a candidate's, but its first
        // page said the metadata ride-along was truncated — rows beyond it
        // (members, bans, mutes, pins of a large channel) may be missing
        // here, and a later session would never page them (it admits no
        // chat). Walk the metadata once with the best such candidate (a
        // non-stale one first), at most once per channel per
        // `RECONCILE_META_FOLLOWUP_INTERVAL`. The walk never marks the
        // channel complete and never moves the throttle (see
        // `ReconcileMetaState`); it keeps the trigger in flight until done.
        // The walk starts after the candidate's first-page prefix (round-2
        // audit N2): this node verified it holds exactly those rows.
        let pick = meta_followup_peers
            .iter()
            .find(|(p, _)| {
                !is_peer_stale(
                    self.peer_reconcile_health.get(p).map(|h| h.consecutive_losses).unwrap_or(0),
                    threshold,
                )
            })
            .or(meta_followup_peers.first())
            .cloned();
        if let Some((peer, prefix_end)) = pick {
            // An unfinished walk with this peer (W2) continues regardless of
            // the follow-up spacing; a new one is spaced.
            let now = Instant::now();
            let resumable = self.reconcile_meta_resume_cursor(channel_id, peer, now).is_some();
            if resumable || self.reconcile_meta_followup_due(channel_id, now) {
                self.start_reconcile_meta_walk(peer, channel_id, 0, 0, prefix_end, true);
            }
        }
        self.release_reconcile_trigger_if_no_siblings(channel_id);
    }

    /// Whether a metadata follow-up walk for `channel_id` may start now; if
    /// so, records `now` (G7). The map is bounded: at the cap, expired
    /// entries are dropped first, and if it is still full no follow-up is
    /// started.
    fn reconcile_meta_followup_due(&mut self, channel_id: u64, now: Instant) -> bool {
        if let Some(last) = self.reconcile_meta_followup_at.get(&channel_id) {
            if now.saturating_duration_since(*last) < RECONCILE_META_FOLLOWUP_INTERVAL {
                return false;
            }
        } else if self.reconcile_meta_followup_at.len() >= MAX_RECONCILE_META_FOLLOWUP_KEYS {
            self.reconcile_meta_followup_at
                .retain(|_, at| now.saturating_duration_since(*at) < RECONCILE_META_FOLLOWUP_INTERVAL);
            if self.reconcile_meta_followup_at.len() >= MAX_RECONCILE_META_FOLLOWUP_KEYS {
                return false;
            }
        }
        self.reconcile_meta_followup_at.insert(channel_id, now);
        true
    }

    /// Updates `peer_reconcile_health` for one comparison candidate based
    /// on a VERIFIED trial outcome (l2-node 0.137.0 — see
    /// `finalize_reconcile_comparison`'s doc comment for why this must
    /// never be fed raw, pre-verification data).
    fn record_reconcile_peer_result(&mut self, peer: PeerId, competitive: bool) {
        let now = Instant::now();
        let Some(health) = self.touch_peer_reconcile_health(peer, now) else {
            // Sybil soft cap reached and this is a brand-new peer —
            // skip tracking rather than growing the map unboundedly
            // (security-audit finding, 2026-09-30, round 1).
            return;
        };
        if competitive {
            health.consecutive_losses = 0;
        } else {
            health.consecutive_losses = health.consecutive_losses.saturating_add(1);
        }
    }

    /// Looks up (or inserts, subject to `PEER_RECONCILE_HEALTH_SOFT_CAP`)
    /// a peer's `peer_reconcile_health` entry and stamps `last_touched`
    /// (l2-node 0.137.0) — shared by `record_reconcile_peer_result` and
    /// the reprobe bookkeeping in `maybe_trigger_backfill`. Returns
    /// `None` only when this is a genuinely NEW peer and the map is
    /// already at its Sybil-defense cap; an existing entry is always
    /// touched and returned regardless of the cap (mirrors
    /// `check_gossip_rate_limit`'s identical pattern).
    fn touch_peer_reconcile_health(
        &mut self,
        peer: PeerId,
        now: Instant,
    ) -> Option<&mut PeerReconcileHealth> {
        if !self.peer_reconcile_health.contains_key(&peer) {
            if self.peer_reconcile_health.len() >= PEER_RECONCILE_HEALTH_SOFT_CAP {
                return None;
            }
            self.peer_reconcile_health.insert(
                peer,
                PeerReconcileHealth {
                    consecutive_losses: 0,
                    last_probed_at: None,
                    last_touched: now,
                },
            );
        }
        let entry = self
            .peer_reconcile_health
            .get_mut(&peer)
            .expect("just inserted or already present");
        entry.last_touched = now;
        Some(entry)
    }

    /// Applies one peer's reconcile response — parse, route through the
    /// router, decide continuation/completion/give-up. Shared by the
    /// direct (non-comparison, continuation-page) response path and
    /// `finalize_reconcile_comparison`'s ranked-trial loop, so there is
    /// exactly one implementation of the admission/completion decision
    /// (l2-node 0.137.0 — extracted from what used to be inline in the
    /// `Message::Response` arm; logic otherwise unchanged from 0.136.0).
    ///
    /// `release_on_no_progress`: `true` for the direct path (there's only
    /// ever one active candidate at a time there, so it's safe to decide
    /// immediately). `false` for a comparison trial — releasing
    /// `reconcile_triggered` after the FIRST failed trial would let a
    /// concurrent re-trigger race the trials still to come; the caller
    /// releases itself exactly once after every candidate has been tried.
    fn apply_reconcile_response(
        &mut self,
        pending: ReconcilePending,
        peer: PeerId,
        response: reconcile::ReconcileResponse,
        release_on_no_progress: bool,
    ) -> ReconcileApplyOutcome {
        // G7 (l2-node 0.152.0): a metadata page of this session's walk.
        if pending.meta.walk.is_some() {
            self.apply_reconcile_meta_page(pending, peer, response);
            return ReconcileApplyOutcome::Handled;
        }
        if response.server_capped {
            debug!(
                peer = %peer,
                channel_id = pending.channel_id,
                "reconcile: peer responded server_capped; ignoring (race siblings may succeed)"
            );
            if release_on_no_progress {
                self.release_reconcile_trigger_if_no_siblings(pending.channel_id);
            }
            return ReconcileApplyOutcome::NoProgress { verified_in_sync: false, meta_followup: false };
        }
        if response.envelopes.is_empty() && !response.has_more {
            debug!(
                peer = %peer,
                channel_id = pending.channel_id,
                "reconcile: peer responded empty + no more; ignoring"
            );
            // Uninformative response (this peer may simply know
            // nothing about the channel, not that it's genuinely
            // empty — the wire protocol can't distinguish the
            // two) — don't claim completion. Once every sibling
            // has responded this way, release the dedup entry so
            // the periodic sweep retries with (possibly
            // different) peers later, rather than leaving the
            // channel stuck "in flight" forever.
            if release_on_no_progress {
                self.release_reconcile_trigger_if_no_siblings(pending.channel_id);
            }
            return ReconcileApplyOutcome::NoProgress { verified_in_sync: false, meta_followup: false };
        }

        let env_count = response.envelopes.len();
        let mut accepted_authors: Vec<(String, u8)> = Vec::new();
        let tally = tally_reconcile_envelopes(
            &self.router,
            &self.storage,
            &peer,
            pending.channel_id,
            &response.envelopes,
            reconcile::max_page_with_ride_alongs(self.backfill_config.max_envelopes_per_response),
            window_start_ms(days_window_secs_max_unlimited(self.backfill_config.max_age_days)),
            &mut accepted_authors,
        );
        self.observe_backfilled_authors(&accepted_authors);
        let ReconcileTally { admitted, newly_accepted, cross_channel_dropped, .. } = tally;
        // G7 (l2-node 0.152.0): only the FIRST page carries the metadata
        // ride-along, so only it can report the ride-along as truncated.
        let meta_truncated = pending.meta.truncated || (pending.pages_fetched == 0 && response.meta_truncated);
        let prefix_end = if pending.pages_fetched == 0 {
            response.meta_next_cursor.clone()
        } else {
            pending.meta.prefix_end.clone()
        };
        // A comparison trial whose first page offered only verified
        // duplicates may serve a metadata follow-up walk (see
        // `ReconcileApplyOutcome`).
        let meta_followup = !release_on_no_progress
            && pending.pages_fetched == 0
            && response.meta_truncated
            && tally.is_verified_dup_page(env_count);
        info!(
            peer = %peer,
            channel_id = pending.channel_id,
            received = env_count,
            admitted,
            newly_accepted,
            cross_channel_dropped,
            has_more = response.has_more,
            "reconcile: applied response batch"
        );

        // Race-winner semantics: cancel sibling outbound requests
        // by dropping their pending entries, but ONLY once this
        // response has contributed real, NEWLY-VERIFIED progress
        // (`newly_accepted > 0` — strictly `RouteResult::Accepted`,
        // never `Duplicate`/`Rejected`/`Invalid`/cross-channel-
        // dropped envelopes). l2-node 0.137.0: for a comparison
        // trial there is nothing left to retain here — every
        // sibling's `pending_reconcile_requests` entry was already
        // removed the moment ITS OWN response/failure arrived, so
        // this is a harmless no-op there; it still matters for the
        // direct (continuation-page) path, where a genuine sibling
        // race can still be in flight.
        //
        // Security-audit findings (2026-09-30, two rounds):
        // cancelling on the mere SHAPE of a response (non-empty
        // envelopes, or has_more) let an attacker win the fanout
        // race with an instant, free, all-garbage response —
        // every honest sibling still in flight got silently
        // dropped on arrival ("response for unknown request_id"
        // above). Round 1 gated this on `admitted > 0` instead,
        // but `admitted` also counts `Duplicate`, which round 2
        // found is JUST as forgeable (see `ReconcilePending::
        // total_accepted`'s doc comment) — so gating cancellation
        // on it left the exact same pre-emption open. Only
        // `newly_accepted` requires a real signature verification
        // to reach.
        if newly_accepted > 0 {
            self.pending_reconcile_requests.retain(|_, p| {
                !(p.channel_id == pending.channel_id && p.peer_id != peer)
            });
        }

        // Audit final pre-mainnet W9: requester-side paging budget.
        // Uses `newly_accepted` (not `admitted`), for the same
        // reason as the sibling-cancellation gate above — an
        // attacker replaying forgeable `Duplicate`s on every page
        // would otherwise reset this to 0 every time and never
        // trip the unproductive-page backstop, stretching a
        // pure-garbage session out to the much larger
        // `MAX_PAGES_PER_SESSION` cap instead.
        let pages_fetched = pending.pages_fetched + 1;
        let consecutive_unproductive_pages = if newly_accepted > 0 {
            0
        } else {
            pending.consecutive_unproductive_pages + 1
        };
        let total_accepted = pending.total_accepted + newly_accepted as u64;
        if pages_fetched >= MAX_PAGES_PER_SESSION {
            warn!(peer = %peer, channel_id = pending.channel_id, pages_fetched, "reconcile: hit page-count backstop; stopping this session");
            // Give up on THIS chain, don't claim completion.
            // Sibling cancellation above is now gated on
            // `newly_accepted > 0`, so another peer's chain for this
            // same channel may still be alive — only release the
            // dedup entry once none remain, so a later periodic
            // sweep (or resubscribe) retries instead of being
            // stuck until process restart, but without piling a
            // redundant extra trigger on top of a still-pending
            // sibling.
            self.note_reconcile_accepted_incomplete(pending.channel_id, total_accepted);
            if release_on_no_progress {
                self.release_reconcile_trigger_if_no_siblings(pending.channel_id);
            }
            return ReconcileApplyOutcome::NoProgress { verified_in_sync: false, meta_followup: false };
        }
        if consecutive_unproductive_pages >= MAX_CONSECUTIVE_UNPRODUCTIVE_PAGES {
            warn!(peer = %peer, channel_id = pending.channel_id, consecutive_unproductive_pages, "reconcile: peer made no progress for too many consecutive pages; stopping this session");
            self.note_reconcile_accepted_incomplete(pending.channel_id, total_accepted);
            if release_on_no_progress {
                self.release_reconcile_trigger_if_no_siblings(pending.channel_id);
            }
            return ReconcileApplyOutcome::NoProgress { verified_in_sync: false, meta_followup: false };
        }

        // Security-audit finding (2026-09-30, round 2, CRITICAL): in a
        // comparison trial (`release_on_no_progress == false`, always a
        // FIRST page — `finalize_reconcile_comparison` only ever
        // constructs `pending` fresh with `pages_fetched: 0`), a
        // candidate claiming `has_more = true` with ZERO verified
        // progress on that very first page must NOT be treated as a
        // win. The `Handled` outcome below (via the has_more branch)
        // used to fire unconditionally on response SHAPE regardless of
        // `newly_accepted`, letting a free-to-mint peer identity pad an
        // oversized or all-`Duplicate` first page, claim `has_more =
        // true`, and win the comparison outright — starving every
        // genuinely-content-bearing sibling ranked below it of ever
        // being tried at all, and resetting its OWN staleness counter
        // to "competitive" for free. This is the exact "cheap response
        // wins the race" bug the whole feature exists to close,
        // reopened via the pagination-claim path instead of the raw-
        // count path round 1 already closed. Rejecting it here as
        // `NoProgress` (before ever dispatching a continuation request,
        // so nothing is left dangling) lets the trial loop correctly
        // move on to the next ranked candidate instead.
        //
        // This does NOT touch the DIRECT (non-comparison) continuation-
        // page path's existing, already-audited tolerance for a
        // single zero-`newly_accepted` page mid-session (bounded by
        // `MAX_CONSECUTIVE_UNPRODUCTIVE_PAGES`) — that path always has
        // `release_on_no_progress == true` and is unaffected.
        //
        // KNOWN LIMITATION (code-audit finding, 2026-09-30, round 3,
        // reviewed and explicitly deferred rather than fixed here): this
        // can reject a genuinely HONEST candidate, not just an
        // adversarial one. `build_response` always pages ascending from
        // the responder's oldest stored message (`reconcile.rs`'s own
        // doc comment) and every fresh trigger restarts at `cursor:
        // None` (never resumes a prior session's cursor). An
        // intermittently-connected honest peer whose oldest history
        // happens to already match ours (all-`Duplicate` on page 1) but
        // who genuinely holds newer gap-filling content on page 2+ gets
        // rejected here on page 1 and never gets a chance to deliver
        // that later page — and since every periodic retry re-fetches
        // the SAME oldest page again, this specific gap shape doesn't
        // self-heal by retrying, unlike most of this feature's other
        // accepted residuals. Not fixed in this pass: doing so (e.g.
        // deferring rather than rejecting a has-more/zero-progress
        // trial, and falling back to it only if every ranked candidate
        // comes up empty) would reopen exactly the ordering/dangling-
        // continuation hazards rounds 2-3 just spent closing, and this
        // codebase's own audit history (`feedback_fixes_cause_
        // regressions`) is proof that "reduce a real bug's severity,
        // then immediately layer a fix for the residual on top" is
        // precisely the pattern that tends to introduce the NEXT
        // regression. Judged acceptable to defer: not a security, data-
        // loss, or DoS-class finding (no category CLAUDE.md marks
        // blocking), the channel still converges via any OTHER
        // candidate whose own page 1 has real content (the common case
        // this feature targets), and it degrades to the SAME "channel
        // doesn't fully backfill via this one mechanism" residual class
        // already accepted elsewhere in this exact file (e.g. private-
        // channel history having no backfill path at all).
        if !release_on_no_progress && response.has_more && newly_accepted == 0 {
            debug_assert_eq!(
                pending.pages_fetched, 0,
                "this guard assumes a comparison trial is always a first page; a \
                 release_on_no_progress=false call with pages_fetched != 0 would \
                 silently bypass it"
            );
            warn!(
                peer = %peer,
                channel_id = pending.channel_id,
                "reconcile: comparison trial claimed has_more with zero verified \
                 progress on its first page; treating as no-progress, not a win"
            );
            return ReconcileApplyOutcome::NoProgress { verified_in_sync: false, meta_followup };
        }

        // Continue paging from the winning peer if the
        // responder signalled more data.
        if response.has_more {
            if let Some(cursor) = response.next_cursor {
                let max_age_secs = if self.backfill_config.max_age_days == u64::MAX {
                    u64::MAX
                } else {
                    self.backfill_config
                        .max_age_days
                        .saturating_mul(24 * 3600)
                };
                let next_req = reconcile::ReconcileRequest {
                    channel_id: pending.channel_id,
                    max_age_secs,
                    cursor: Some(cursor),
                    fingerprint: Vec::new(),
                    epoch_root_known: None,
                    round: 0,
                    meta_cursor: None,
                    revision: reconcile::RECONCILE_REVISION,
                };
                let next_id = self
                    .swarm
                    .behaviour_mut()
                    .reconcile
                    .send_request(&pending.peer_id, next_req);
                self.pending_reconcile_requests.insert(
                    next_id,
                    ReconcilePending {
                        peer_id: pending.peer_id,
                        channel_id: pending.channel_id,
                        pages_fetched,
                        consecutive_unproductive_pages,
                        total_accepted,
                        meta: ReconcileMetaState { truncated: meta_truncated, prefix_end: prefix_end.clone(), walk: None },
                    },
                );
                ReconcileApplyOutcome::Handled
            } else {
                // Code-audit finding (2026-09-30): a peer
                // signalling `has_more = true` with no cursor is
                // a wire-protocol violation (this node's own
                // `build_response` never emits that combination,
                // but the response is untrusted). Neither
                // "continue paging" nor "natural completion"
                // applies — give up on this chain the same way
                // the backstops above do, instead of silently
                // falling through and leaving the dedup entry
                // (and any still-alive siblings' fate) stuck.
                warn!(peer = %peer, channel_id = pending.channel_id, "reconcile: peer signalled has_more with no cursor; stopping this session");
                self.note_reconcile_accepted_incomplete(pending.channel_id, total_accepted);
                if release_on_no_progress {
                    self.release_reconcile_trigger_if_no_siblings(pending.channel_id);
                }
                ReconcileApplyOutcome::NoProgress { verified_in_sync: false, meta_followup: false }
            }
        } else if total_accepted > 0 {
            // Natural completion: this session got at least one
            // genuinely NEW, signature-verified envelope
            // (`RouteResult::Accepted` — never `Duplicate`, see
            // `ReconcilePending::total_accepted`'s doc comment for
            // why `Duplicate` is excluded, AND for the still-open
            // "single race-winning peer can fabricate this with
            // one self-signed throwaway message" residual — not
            // fully closed by this gate, only made time-bounded).
            // Still strictly better than the prior any-row proxy
            // this replaces (2026-09-30) — it requires a real
            // signature over genuinely new content, not "we
            // happen to have at least one local row" or "the
            // response merely wasn't shaped like the
            // empty-and-no-more case."
            //
            // G7 (l2-node 0.152.0): when the first page's metadata
            // ride-along was truncated, the channel is not complete until
            // the metadata walk with this same peer reached its end too —
            // the walk marks completion itself (`apply_reconcile_meta_page`).
            if meta_truncated {
                self.start_reconcile_meta_walk(
                    pending.peer_id,
                    pending.channel_id,
                    pages_fetched,
                    total_accepted,
                    prefix_end,
                    false,
                );
                return ReconcileApplyOutcome::Handled;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if let Err(e) = self
                .storage
                .mark_channel_backfill_complete(pending.channel_id, now)
            {
                warn!(channel_id = pending.channel_id, error = %e, "reconcile: failed to persist backfill completion");
            }
            // l2-node 0.141.0: COMPLETE — forget the throttle entry; the
            // persisted marker + `channel_catchup_interval_hours` take over.
            self.reconcile_throttle.on_complete(&pending.channel_id);
            self.release_reconcile_trigger_if_no_siblings(pending.channel_id);
            ReconcileApplyOutcome::Handled
        } else {
            // Security-audit findings (2026-09-30, two rounds): a
            // response can be non-empty (so it skips the
            // empty+no-more early return above) yet contribute
            // ZERO genuinely new, verified envelopes — round 1's
            // example was a single garbage byte that fails to
            // deserialize; round 2's was a forged envelope
            // replaying a msg_id that already exists ANYWHERE on
            // this node (any channel), which reaches
            // `RouteResult::Duplicate` with no signature check at
            // all. Gating on `total_accepted` (strictly
            // `Accepted`) rather than `total_admitted` (which
            // included `Duplicate`) closes both — this is a
            // give-up, not a completion, either way. Note this
            // also correctly covers the legitimate steady-state
            // case where a peer confirms "you already have
            // everything" via all-`Duplicate` responses: that
            // does NOT refresh `mark_channel_backfill_complete`
            // either, so such a channel keeps getting
            // re-attempted every periodic-sweep tick rather than
            // going quiet — in exchange for never trusting an
            // unverifiable signal. Round-3 security audit: this
            // is a real, NOT fully quiescing steady-state cost —
            // v0.47.0 always "bulk-sends everything" (no
            // fingerprint diffing yet), so a fully-synced,
            // all-Duplicate channel still pages through and
            // deserializes real envelope batches on every
            // periodic-sweep retry (up to `MAX_CONSECUTIVE_
            // UNPRODUCTIVE_PAGES` x `max_envelopes_per_response`
            // per cycle), forever, for every such channel — not
            // merely a cheap point-read like the genuinely-empty-
            // channel case. Bounded per-tick/per-session, so not
            // DoS-class, but worth tracking as a real cost that
            // only goes away once spec-14 fingerprinting lands.
            //
            // l2-node 0.141.0: that steady-state cost is now throttled
            // requester-side (`reconcile_throttle`): a comparison whose
            // candidates all prove a verified in-sync first page
            // (`is_verified_in_sync_page`, judged by `comparison_in_sync`)
            // is rechecked after `in_sync_recheck_minutes`; anything else
            // backs off exponentially. Still never COMPLETE.
            let verified_in_sync = !release_on_no_progress
                && pending.pages_fetched == 0
                && tally.is_verified_in_sync_page(env_count, response.has_more);
            if verified_in_sync {
                debug!(peer = %peer, channel_id = pending.channel_id, verified_dups = tally.verified_dups, "reconcile: first page is a verified in-sync page (nothing new); not marking complete");
            } else {
                warn!(peer = %peer, channel_id = pending.channel_id, "reconcile: session ended with has_more=false but zero newly-accepted envelopes; not marking complete");
            }
            if release_on_no_progress {
                self.release_reconcile_trigger_if_no_siblings(pending.channel_id);
            }
            ReconcileApplyOutcome::NoProgress { verified_in_sync, meta_followup }
        }
    }

    /// `[backfill] max_age_days` as the reconcile request's `max_age_secs`
    /// (`u64::MAX` = archive mode).
    fn reconcile_max_age_secs(&self) -> u64 {
        if self.backfill_config.max_age_days == u64::MAX {
            u64::MAX
        } else {
            self.backfill_config.max_age_days.saturating_mul(24 * 3600)
        }
    }

    /// Ask `peer` for the first metadata page of `channel_id` (l2-node
    /// 0.152.0, G7) and register the walk as a pending session page.
    /// `followup` = a walk after a no-winner comparison (never completes the
    /// channel, see `ReconcileMetaState`).
    ///
    /// Start position (round-1 audits B2, W2): the larger of the first page's
    /// prefix end (`prefix_end`) and an unfinished earlier walk's position
    /// with this peer (`reconcile_meta_resume`), else `MetaCursor::START`.
    /// Every row before it was already applied in order, so the walk never
    /// replays an older row after a newer one of the same session.
    fn start_reconcile_meta_walk(
        &mut self,
        peer: PeerId,
        channel_id: u64,
        pages_fetched: u32,
        total_accepted: u64,
        prefix_end: Option<reconcile::MetaCursor>,
        followup: bool,
    ) {
        let resume = self.reconcile_meta_resume_cursor(channel_id, peer, Instant::now());
        let start = std::cmp::max(prefix_end, resume).unwrap_or(reconcile::MetaCursor::START);
        let req = reconcile::ReconcileRequest {
            channel_id,
            max_age_secs: self.reconcile_max_age_secs(),
            cursor: None,
            fingerprint: Vec::new(),
            epoch_root_known: None,
            round: 0,
            meta_cursor: Some(start.clone()),
            revision: reconcile::RECONCILE_REVISION,
        };
        debug!(peer = %peer, channel_id, followup, "reconcile: paging channel metadata");
        let id = self.swarm.behaviour_mut().reconcile.send_request(&peer, req);
        self.pending_reconcile_requests.insert(
            id,
            ReconcilePending {
                peer_id: peer,
                channel_id,
                pages_fetched,
                consecutive_unproductive_pages: 0,
                total_accepted,
                meta: ReconcileMetaState {
                    truncated: true,
                    prefix_end: None,
                    walk: Some(MetaWalk { last_cursor: start, pages: 0, followup }),
                },
            },
        );
    }

    /// The live (not expired) resume position of an unfinished metadata
    /// walk of `channel_id` with `peer` (W2).
    fn reconcile_meta_resume_cursor(&self, channel_id: u64, peer: PeerId, now: Instant) -> Option<reconcile::MetaCursor> {
        self.reconcile_meta_resume
            .get(&(channel_id, peer))
            .filter(|(_, at)| now.saturating_duration_since(*at) < RECONCILE_META_RESUME_TTL)
            .map(|(c, _)| c.clone())
    }

    /// Remember where an unfinished walk with `peer` must continue (W2).
    /// Bounded: at the cap expired entries are dropped first; if still full
    /// the position is not kept.
    fn remember_reconcile_meta_resume(&mut self, channel_id: u64, peer: PeerId, cursor: reconcile::MetaCursor) {
        let now = Instant::now();
        let key = (channel_id, peer);
        if !self.reconcile_meta_resume.contains_key(&key) && self.reconcile_meta_resume.len() >= MAX_RECONCILE_META_RESUME_KEYS {
            self.reconcile_meta_resume
                .retain(|_, (_, at)| now.saturating_duration_since(*at) < RECONCILE_META_RESUME_TTL);
            if self.reconcile_meta_resume.len() >= MAX_RECONCILE_META_RESUME_KEYS {
                return;
            }
        }
        self.reconcile_meta_resume.insert(key, (cursor, now));
    }

    /// Apply one metadata page of a reconcile metadata walk (l2-node
    /// 0.152.0, G7) and decide: next page, completion, or stop. Pages are
    /// verified like chat pages (`tally_reconcile_envelopes`: channel
    /// binding, router re-validation, in replay order) and may carry only
    /// metadata types. A page with any non-metadata envelope, or with more
    /// than `CHANNEL_META_PAGE_MAX` envelopes, is not applied and STOPS the
    /// walk unfinished (round-1 audit W1: it can never complete the
    /// channel). A walk stopped by a capped / failed / non-metadata answer or
    /// the page backstop keeps its position for the next walk with this
    /// peer (W2); a non-advancing cursor does not. Metadata pages
    /// are never "unproductive" (a re-walk legitimately re-serves rows as
    /// duplicates); they are bounded by the strictly advancing cursor and
    /// `MAX_RECONCILE_META_PAGES`. See `ReconcileMetaState` for when the
    /// channel counts complete.
    fn apply_reconcile_meta_page(
        &mut self,
        pending: ReconcilePending,
        peer: PeerId,
        response: reconcile::ReconcileResponse,
    ) {
        let channel_id = pending.channel_id;
        let Some(walk) = pending.meta.walk.clone() else {
            return;
        };
        let mut total_accepted = pending.total_accepted;
        // `Some(true)` = walked to the end, `Some(false)` = stopped early,
        // `None` = continue with `next`.
        let mut finished: Option<bool> = None;
        let mut next: Option<reconcile::MetaCursor> = None;
        // Position to continue from if the walk stops here (W2).
        let mut resume_at: Option<reconcile::MetaCursor> = None;
        if response.server_capped || !response.meta_page {
            // Capped, or not a metadata page at all (e.g. the responder was
            // downgraded mid-session): stop, never guess.
            debug!(peer = %peer, channel_id, capped = response.server_capped, "reconcile: metadata walk stopped (capped or not a metadata page)");
            finished = Some(false);
            resume_at = Some(walk.last_cursor.clone());
        } else if response.envelopes.len() > reconcile::CHANNEL_META_PAGE_MAX
            || !response.envelopes.iter().all(|e| reconcile::envelope_is_meta_type(e))
        {
            warn!(
                peer = %peer,
                channel_id,
                received = response.envelopes.len(),
                "reconcile: metadata page oversized or carrying non-metadata envelopes; not applied, walk stopped"
            );
            finished = Some(false);
        } else {
            let received = response.envelopes.len();
            let mut accepted_authors: Vec<(String, u8)> = Vec::new();
            let tally = tally_reconcile_envelopes(
                &self.router,
                &self.storage,
                &peer,
                channel_id,
                &response.envelopes,
                reconcile::CHANNEL_META_PAGE_MAX,
                0,
                &mut accepted_authors,
            );
            self.observe_backfilled_authors(&accepted_authors);
            total_accepted = total_accepted.saturating_add(tally.newly_accepted as u64);
            info!(
                peer = %peer,
                channel_id,
                received,
                newly_accepted = tally.newly_accepted,
                meta_truncated = response.meta_truncated,
                "reconcile: applied metadata page"
            );
            let pages = walk.pages.saturating_add(1);
            if !response.meta_truncated {
                finished = Some(true);
            } else {
                match response.meta_next_cursor {
                    Some(c) if c > walk.last_cursor && pages < MAX_RECONCILE_META_PAGES => next = Some(c),
                    Some(c) if c > walk.last_cursor => {
                        // Page backstop: keep the position for the next walk.
                        warn!(peer = %peer, channel_id, pages, "reconcile: metadata walk stopped at the page backstop; resumes next session");
                        finished = Some(false);
                        resume_at = Some(c);
                    }
                    _ => {
                        warn!(peer = %peer, channel_id, pages, "reconcile: metadata walk stopped (no advancing cursor)");
                        finished = Some(false);
                    }
                }
            }
        }

        if let Some(cursor) = next {
            let req = reconcile::ReconcileRequest {
                channel_id,
                max_age_secs: self.reconcile_max_age_secs(),
                cursor: None,
                fingerprint: Vec::new(),
                epoch_root_known: None,
                round: 0,
                meta_cursor: Some(cursor.clone()),
                revision: reconcile::RECONCILE_REVISION,
            };
            let id = self.swarm.behaviour_mut().reconcile.send_request(&peer, req);
            self.pending_reconcile_requests.insert(
                id,
                ReconcilePending {
                    total_accepted,
                    meta: ReconcileMetaState {
                        truncated: true,
                        prefix_end: None,
                        walk: Some(MetaWalk { last_cursor: cursor, pages: walk.pages.saturating_add(1), followup: walk.followup }),
                    },
                    ..pending
                },
            );
            return;
        }

        if finished == Some(true) {
            self.reconcile_meta_resume.remove(&(channel_id, peer));
        } else if let Some(c) = resume_at {
            self.remember_reconcile_meta_resume(channel_id, peer, c);
        }
        match (finished, walk.followup) {
            // In-session walk reached the end: the chat phase admitted new
            // content (that is the only way an in-session walk starts), so
            // the channel is complete.
            (Some(true), false) if total_accepted > 0 => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if let Err(e) = self.storage.mark_channel_backfill_complete(channel_id, now) {
                    warn!(channel_id, error = %e, "reconcile: failed to persist backfill completion");
                }
                self.reconcile_throttle.on_complete(&channel_id);
            }
            // In-session walk stopped early: not complete; retry soon (new
            // content was admitted).
            (_, false) => self.note_reconcile_accepted_incomplete(channel_id, total_accepted),
            // Follow-up: purely additive, the comparison's verdict stands.
            (_, true) => {}
        }
        self.release_reconcile_trigger_if_no_siblings(channel_id);
    }

    /// Throttle outcome for a session that admitted new content
    /// (`total_accepted > 0`) but stopped before the end (a backstop or a
    /// protocol violation): retry in 30 s with the backoff reset (l2-node
    /// 0.141.0). A session with nothing accepted keeps its dispatch backoff.
    fn note_reconcile_accepted_incomplete(&mut self, channel_id: u64, total_accepted: u64) {
        if total_accepted > 0 {
            self.reconcile_throttle
                .on_accepted_incomplete(channel_id, Instant::now());
        }
    }

    /// Process the reconnect queue: attempt to redial peers whose backoff has expired.
    fn process_reconnect_queue(&mut self) {
        if self.reconnect_queue.is_empty() {
            return;
        }

        let now = tokio::time::Instant::now();
        let mut i = 0;
        while i < self.reconnect_queue.len() {
            let entry = &self.reconnect_queue[i];
            if now < entry.next_attempt {
                i += 1;
                continue;
            }

            // Already reconnected? Remove from queue.
            if self.swarm.is_connected(&entry.peer_id) {
                self.reconnect_queue.swap_remove(i);
                continue;
            }

            // Max attempts exceeded? Give up and clean up.
            if entry.attempts >= MAX_RECONNECT_ATTEMPTS {
                let peer = entry.peer_id;
                debug!(
                    peer = %peer,
                    attempts = entry.attempts,
                    "Giving up on reconnection"
                );
                self.known_peer_addrs.remove(&peer);
                self.remove_persisted_peer(&peer);
                self.reconnect_queue.swap_remove(i);
                continue;
            }

            // Attempt redial
            let addr = entry.addr.clone();
            let peer = entry.peer_id;
            let attempts = entry.attempts + 1;
            let new_backoff = (entry.backoff_secs * 2).min(RECONNECT_MAX_SECS);

            match self.swarm.dial(addr.clone()) {
                Ok(_) => {
                    debug!(
                        peer = %peer,
                        attempt = attempts,
                        next_backoff = new_backoff,
                        "Reconnection attempt"
                    );
                }
                // Refused locally by the pending-dial cap (the only limit
                // checked synchronously in `dial`): says nothing about the
                // peer, so retry
                // soon without counting an attempt — otherwise a burst of
                // in-flight dials could evict healthy peers from the book.
                Err(libp2p::swarm::DialError::Denied { .. }) => {
                    self.reconnect_queue[i].next_attempt = now + Duration::from_secs(30);
                    i += 1;
                    continue;
                }
                Err(e) => {
                    debug!(
                        peer = %peer,
                        error = %e,
                        "Reconnection dial failed"
                    );
                }
            }

            // Update backoff for next attempt
            self.reconnect_queue[i].attempts = attempts;
            self.reconnect_queue[i].backoff_secs = new_backoff;
            self.reconnect_queue[i].next_attempt =
                now + Duration::from_secs(new_backoff);
            i += 1;
        }
    }

    /// Queue a disconnected peer for reconnection with exponential backoff.
    fn queue_reconnect(&mut self, peer_id: PeerId) {
        // Don't queue if already in the queue
        if self.reconnect_queue.iter().any(|e| e.peer_id == peer_id) {
            return;
        }

        // Need a known address to reconnect
        let addr = match self.known_peer_addrs.get(&peer_id) {
            Some(a) => a.clone(),
            None => return, // no address known, can't reconnect
        };

        // Cap queue size to prevent unbounded growth from mass disconnections
        if self.reconnect_queue.len() >= 128 {
            debug!("Reconnect queue full, dropping entry");
            self.reconnect_queue.swap_remove(0); // O(1) vs O(n) for remove(0)
        }

        self.reconnect_queue.push(ReconnectEntry {
            peer_id,
            addr,
            next_attempt: tokio::time::Instant::now()
                + Duration::from_secs(RECONNECT_BASE_SECS),
            backoff_secs: RECONNECT_BASE_SECS,
            attempts: 0,
        });

        debug!(peer = %peer_id, "Queued peer for reconnection");
    }

    /// Handle a request-response event — sync protocol.
    ///
    /// Inbound requests: build response from local storage and send it back.
    /// Inbound responses: validate and store each message.
    fn handle_request_response(
        &mut self,
        event: libp2p::request_response::Event<sync::SyncRequest, sync::SyncResponse>,
    ) {
        use libp2p::request_response;

        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request,
                        channel,
                        ..
                    },
                ..
            } => {
                debug!(
                    peer = %peer,
                    request_type = ?request.request_type,
                    channel_id = ?request.channel_id,
                    "Received sync request"
                );

                // Audit final pre-mainnet W7: rate-limit + cumulative cap
                // before doing any storage work, mirroring reconcile's
                // Request-arm handling. Reuses `reconcile::ResponderLimits`
                // directly (see `sync_limits`'s field doc). Unimplemented
                // request types (no live requester) fall back to
                // `channel_id.unwrap_or(0)` — gating them too is harmless
                // (they already produce an empty response for free) and
                // keeps this uniform with every other protocol's
                // unconditional gating. Security-audit follow-up: this
                // shared bucket relies on `channel_id == 0` never being a
                // valid channel (enforced in `messages/validation.rs`, 11
                // separate checks) — if that invariant ever changes, this
                // would silently become a starvation vector between free
                // stub-type spam and legitimate channel-0 traffic.
                let request_type = request.request_type;
                let channel_id = request.channel_id.unwrap_or(0);
                let sync_budget =
                    budget::Gcra::new(sync::TOTAL_ENVELOPES_CAP, SYNC_RESPONDER_REFILL_PER_HOUR);
                let now_instant = Instant::now();
                let guard = self
                    .sync_limits
                    .try_acquire(
                        peer,
                        channel_id,
                        sync::SERVER_MAX_CONCURRENT_PER_PEER,
                        sync::SERVER_MAX_CONCURRENT_PER_CHANNEL,
                        &sync_budget,
                        now_instant,
                    )
                    .ok();
                let response = if guard.is_none() {
                    debug!(
                        peer = %peer,
                        channel_id,
                        "sync: rate-limited or session-cap exhausted; \
                         responding server_capped"
                    );
                    sync::capped_response(request_type)
                } else {
                    sync::build_sync_response(request, &self.storage)
                };

                info!(
                    peer = %peer,
                    messages = response.messages.len(),
                    has_more = response.has_more,
                    server_capped = response.server_capped,
                    "Sending sync response"
                );

                if !response.messages.is_empty() {
                    self.sync_limits.charge(
                        peer,
                        channel_id,
                        response.messages.len() as u64,
                        &sync_budget,
                        now_instant,
                    );
                }

                if self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, response)
                    .is_err()
                {
                    warn!(peer = %peer, "Failed to send sync response (channel closed)");
                }
            }

            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                info!(
                    peer = %peer,
                    request_type = ?response.request_type,
                    messages = response.messages.len(),
                    has_more = response.has_more,
                    server_capped = response.server_capped,
                    "Received sync response"
                );

                // Audit final pre-mainnet W7: look up which channel THIS
                // request was for; drop any envelope that doesn't match
                // (smuggling defense — mirrors reconcile's
                // `envelope_targets_channel` check on its own response
                // path). An unknown request_id (already handled, or from a
                // race) is logged and ignored, same shape as reconcile's
                // "response for unknown request_id" case.
                let Some(expected_channel) = self.pending_sync_requests.remove(&request_id)
                else {
                    debug!(
                        peer = %peer,
                        ?request_id,
                        "sync: response for unknown request_id (already handled or stale)"
                    );
                    return;
                };

                if response.server_capped {
                    debug!(
                        peer = %peer,
                        expected_channel,
                        "sync: peer responded server_capped; back off"
                    );
                    return;
                }

                let mut accepted = 0u32;
                let mut rejected = 0u32;
                let mut cross_channel_dropped = 0u32;
                let deletion_min_ts =
                    window_start_ms(days_window_secs_max_unlimited(self.backfill_config.max_age_days));
                for msg_bytes in &response.messages {
                    if !envelope_targets_channel(msg_bytes, expected_channel) {
                        cross_channel_dropped += 1;
                        continue;
                    }
                    // l2-node 0.151.0 (audit note 6): bind a DeletionRequest
                    // to this channel and window like every other receiver.
                    match deletion_request_fit(
                        &self.storage,
                        msg_bytes,
                        DeletionScope::Channel(expected_channel),
                        deletion_min_ts,
                    ) {
                        DeletionFit::Fits => {}
                        DeletionFit::Neutral => continue,
                        DeletionFit::Malformed => {
                            cross_channel_dropped += 1;
                            continue;
                        }
                    }
                    self.counters.add_bytes_in(msg_bytes.len() as u64);
                    self.counters.inc_messages_received();
                    match self.router.process_synced_message(msg_bytes) {
                        RouteResult::Accepted { .. } => {
                            self.counters.inc_messages_stored();
                            accepted += 1;
                        }
                        RouteResult::Duplicate => {}
                        RouteResult::Rejected(reason) | RouteResult::Invalid(reason) => {
                            self.counters.inc_failed_validations();
                            warn!(reason = %reason, "Rejected synced message");
                            rejected += 1;
                        }
                        RouteResult::PowRequired { .. } => {
                            // PoW not enforced for synced messages
                            rejected += 1;
                        }
                        // Key-epoch arbitration loss (0.143.0): a sync-path rejection.
                        RouteResult::KeyConflict(_) => rejected += 1,
                    }
                }
                if cross_channel_dropped > 0 {
                    warn!(
                        peer = %peer,
                        expected_channel,
                        cross_channel_dropped,
                        "sync: dropped envelopes targeting a different channel than requested"
                    );
                }
                if accepted > 0 || rejected > 0 {
                    info!(accepted, rejected, "Sync response processed");
                }
            }

            request_response::Event::OutboundFailure {
                peer, request_id, error, ..
            } => {
                self.pending_sync_requests.remove(&request_id);
                warn!(peer = %peer, error = %error, "Sync request failed");
            }

            request_response::Event::InboundFailure {
                peer, error, ..
            } => {
                warn!(peer = %peer, error = %error, "Sync inbound failure");
            }

            _ => {}
        }
    }

    /// Handle an incoming snapshot-protocol request-response event
    /// (spec 11-snapshot-sync.md). Phase 1: serves cached chunks; the
    /// outbound (client) side is wired in Phase 2.
    fn handle_snapshot_event(
        &mut self,
        event: libp2p::request_response::Event<
            self::snapshot::SnapshotRequest,
            self::snapshot::SnapshotResponse,
        >,
    ) {
        use libp2p::request_response;

        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request,
                        channel,
                        ..
                    },
                ..
            } => {
                debug!(peer = %peer, request = ?request, "Received snapshot request");

                // Concurrency gate (audit 2026-06-07 W8). `GetChunk` is the
                // expensive arm; `GetManifest` is a cheap cached read but was
                // previously UNGATED, so a peer could flood it. Both now take a
                // permit (manifest holds it only briefly, so it can't
                // meaningfully starve chunk serving); `Advertise` stays free.
                // The permit is held until the response is sent to bound the
                // working set across the libp2p task. `try_acquire_owned` is
                // non-blocking — under load we return `RateLimited` immediately
                // so the peer falls over to a different mirror in Phase 2+.
                let _permit_guard = if matches!(
                    request,
                    self::snapshot::SnapshotRequest::GetChunk { .. }
                        | self::snapshot::SnapshotRequest::GetManifest { .. }
                ) {
                    match self.snapshot_chunk_semaphore.clone().try_acquire_owned() {
                        Ok(p) => Some(p),
                        Err(_) => {
                            warn!(
                                peer = %peer,
                                "Snapshot chunk request rate-limited (max concurrent reached)"
                            );
                            let resp = self::snapshot::SnapshotResponse::Error {
                                code: self::snapshot::SnapshotErrorCode::RateLimited,
                                message: "snapshot serve at capacity".into(),
                            };
                            if self
                                .swarm
                                .behaviour_mut()
                                .snapshot
                                .send_response(channel, resp)
                                .is_err()
                            {
                                warn!(peer = %peer, "Failed to send RateLimited response (channel closed)");
                            }
                            return;
                        }
                    }
                } else {
                    None
                };

                let response = self::snapshot::build_response(
                    &self.snapshot_cache,
                    self.snapshot_serve_enabled,
                    request,
                );

                if self
                    .swarm
                    .behaviour_mut()
                    .snapshot
                    .send_response(channel, response)
                    .is_err()
                {
                    warn!(peer = %peer, "Failed to send snapshot response (channel closed)");
                }
            }

            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        response,
                        request_id,
                        ..
                    },
                ..
            } => {
                // Phase 2: deliver the response back to the snapshot client
                // task waiting on this request_id. If we have no waiter, the
                // request was either issued by Phase 1 (no longer happens)
                // or the bootstrap task gave up and dropped the receiver.
                match self.pending_snapshot_requests.remove(&request_id) {
                    Some(reply) => {
                        let _ = reply.send(Ok(response));
                    }
                    None => {
                        debug!(peer = %peer, ?request_id, "Snapshot response without pending waiter (bootstrap timed out?)");
                    }
                }
            }

            request_response::Event::OutboundFailure { peer, error, request_id, .. } => {
                warn!(peer = %peer, error = %error, ?request_id, "Snapshot outbound request failed");
                if let Some(reply) = self.pending_snapshot_requests.remove(&request_id) {
                    let _ = reply.send(Err(SnapshotClientError::OutboundFailure(error.to_string())));
                }
            }

            request_response::Event::InboundFailure { peer, error, .. } => {
                warn!(peer = %peer, error = %error, "Snapshot inbound failure");
            }

            _ => {}
        }
    }

    /// Dispatch a snapshot-client command onto the swarm.
    ///
    /// `SendRequest` parks the caller's `oneshot::Sender` in
    /// `pending_snapshot_requests` keyed by libp2p's `OutboundRequestId`;
    /// the response (or failure) arm of `handle_snapshot_event` resolves
    /// the oneshot. `ListConnectedPeers` answers synchronously.
    fn handle_snapshot_client_command(&mut self, cmd: SnapshotClientCommand) {
        match cmd {
            SnapshotClientCommand::SendRequest { peer, request, reply } => {
                // Bound the pending-request map. A malicious peer churn
                // pattern (connect, get many requests sent, disconnect,
                // repeat) can leak entries between dispatch and the libp2p
                // OutboundFailure event. The bootstrap path issues at most
                // a few thousand requests total, so 8192 is plenty of
                // headroom while still bounding the worst case.
                // (Audit finding Phase 2 Code W2.)
                const MAX_PENDING_SNAPSHOT_REQUESTS: usize = 8192;

                // Opportunistic GC: drop any entries whose receiver was
                // dropped (caller timed out and gave up). Cheap, runs on
                // every SendRequest to amortize cost across the bootstrap.
                self.pending_snapshot_requests
                    .retain(|_, sender| !sender.is_closed());

                if self.pending_snapshot_requests.len() >= MAX_PENDING_SNAPSHOT_REQUESTS {
                    warn!(
                        pending = self.pending_snapshot_requests.len(),
                        "Snapshot pending-request map at cap — dropping new request"
                    );
                    let _ = reply.send(Err(SnapshotClientError::OutboundFailure(
                        "snapshot client request cap reached".into(),
                    )));
                    return;
                }
                let id = self
                    .swarm
                    .behaviour_mut()
                    .snapshot
                    .send_request(&peer, request);
                self.pending_snapshot_requests.insert(id, reply);
            }
            SnapshotClientCommand::ListConnectedPeers { reply } => {
                let peers: Vec<PeerId> = self.swarm.connected_peers().copied().collect();
                let _ = reply.send(peers);
            }
        }
    }

    /// Initiate sync for all subscribed channels with a connected peer.
    ///
    /// Called when a new peer connection is established. Sends a SyncRequest
    /// for each channel the node is subscribed to, requesting messages after
    /// the latest message the node already has for that channel.
    fn sync_channels_with_peer(&mut self, peer_id: PeerId) {
        // Security-audit finding (2026-10-06, round 3): this used to send
        // a generic `SyncRequest` for EVERY subscribed channel — private
        // ones included — to every peer the moment Identify succeeds, no
        // membership check, no peer relationship required. That's a
        // worse enumeration surface than the REST/gossip leaks fixed
        // alongside it: those require a query or a propagation wait,
        // this pushes the node's full private channel_id list to any
        // peer for free just by connecting. Private channel MESSAGE
        // backfill already has its own dedicated, auth'd, membership-
        // gated protocol (`PrivateChannelSyncRequest`/
        // `maybe_trigger_private_channel_sync`, `private_channel_sync.rs`)
        // that this generic loop never touches — so restricting this one
        // to public/read-public channels loses no legitimate private-
        // channel sync path, it only stops leaking the id list.
        let channel_ids: Vec<u64> = self.topics.subscribed_public_channels();

        if channel_ids.is_empty() {
            return;
        }

        info!(
            peer = %peer_id,
            channels = channel_ids.len(),
            "Starting sync with peer"
        );

        for channel_id in channel_ids {
            // Find the latest message timestamp for this channel to avoid re-fetching
            let after_timestamp = self
                .storage
                .latest_channel_timestamp(channel_id)
                .unwrap_or(None);

            let request = sync::SyncRequest {
                request_type: sync::SyncRequestType::ChannelMessages,
                channel_id: Some(channel_id),
                conversation_id: None,
                before_id: None,
                after_id: None,
                after_timestamp,
                limit: 500,
            };

            let request_id = self
                .swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, request);
            // Audit final pre-mainnet W7: remember which channel this
            // request was for, so the response handler can reject envelopes
            // for any OTHER channel (a responder answering a ChannelMessages
            // request for channel A with envelopes for channel B).
            self.pending_sync_requests.insert(request_id, channel_id);
        }
    }

    /// Publish a NodeAnnouncement to the /ogmara/{network}/v1/network topic.
    ///
    /// Announces this node's presence, capabilities, and served channels
    /// so other nodes can discover it and the website can list it.
    fn publish_node_announcement(&mut self) {
        use crate::messages::envelope::{Envelope, PROTOCOL_VERSION};
        use crate::messages::types::{Capability, MessageType, NodeAnnouncementPayload};

        // Security-audit follow-up (2026-10-06, found while fixing the
        // `/api/v1/network/nodes` enumeration leak): `subscribed_channels`
        // has no public/private distinction — `federate_channel` calls
        // the exact same `subscribe_channel` a chain-discovered PUBLIC
        // channel does. Without this filter, every private channel_id
        // this node has ever federated gets broadcast network-wide in
        // the clear, contradicting this payload's own documented
        // guarantee (protocol spec 01 §network: "Private channels are
        // NOT announced... no metadata leakage to the network") and
        // reintroducing the SAME enumerability weakening the identity-
        // binding fix (l2-node 0.139.0) is specifically meant to avoid —
        // an attacker who can enumerate N real private ids searches one
        // Keccak stream against all of them, cutting the expected
        // forgery cost from ~2^53 to ~2^53/N.
        let channels: Vec<u64> = self.topics.subscribed_public_channels();
        let user_count = self
            .storage
            .get_stat(crate::storage::schema::state_keys::TOTAL_USERS)
            .unwrap_or(0) as u32;

        // Snapshot fields are only set when the cache builder has produced
        // at least one snapshot. Older nodes that don't deserialize the
        // new fields fall through via `#[serde(default)]`.
        let (snapshot_height, snapshot_root) = match self.snapshot_cache.read() {
            Ok(guard) => match guard.as_ref() {
                Some(c) => (
                    Some(c.manifest.block_height),
                    Some(hex::encode(c.manifest.snapshot_root)),
                ),
                None => (None, None),
            },
            Err(_) => (None, None),
        };

        let payload = NodeAnnouncementPayload {
            node_id: self.node_id.clone(),
            channels,
            user_count,
            capabilities: vec![
                Capability::Chat,
                Capability::News,
                Capability::Sync,
            ],
            api_endpoint: self.public_url.clone(),
            ttl_seconds: 600, // 10 minutes
            snapshot_height,
            snapshot_root,
        };

        let payload_bytes = match rmp_serde::to_vec(&payload) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to serialize NodeAnnouncement");
                return;
            }
        };

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let author = match crate::crypto::pubkey_to_address(&self.signing_key.verifying_key()) {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "Failed to compute node address");
                return;
            }
        };

        // msg_id + signature via the shared, network-bound helpers (fixed
        // alongside audit 2026-08-16 C1: this hand-rolled preimage never
        // matched `verify_ogmara_message`/`verify_klever_message` — neither
        // has a domain separator nor a Klever prefix over a bare msg_id sign
        // — so NodeAnnouncement envelopes were unconditionally rejected by
        // every receiver's `verify_signature`, pre-existing and unrelated to
        // C1. Using `crypto::compute_msg_id`/`signing::sign_ogmara_message`
        // fixes that AND gets network binding for free.
        let network = self.topics.network_id();
        let pubkey_bytes = self.signing_key.verifying_key().to_bytes();
        let msg_id =
            crate::crypto::compute_msg_id(network, &pubkey_bytes, &payload_bytes, now_ms);
        let signature = crate::crypto::signing::sign_ogmara_message(
            &self.signing_key,
            network,
            PROTOCOL_VERSION,
            MessageType::NodeAnnouncement as u8,
            &msg_id,
            now_ms,
            &payload_bytes,
        );

        let envelope = Envelope {
            version: PROTOCOL_VERSION,
            msg_type: MessageType::NodeAnnouncement,
            msg_id,
            author,
            timestamp: now_ms,
            lamport_ts: 0, // announcements don't need causal ordering
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: Vec::new(),
        };

        let envelope_bytes = match rmp_serde::to_vec(&envelope) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to serialize announcement envelope");
                return;
            }
        };

        let topic = libp2p::gossipsub::IdentTopic::new(gossip::topic_network(self.topics.network_id()));
        match self.swarm.behaviour_mut().gossipsub.publish(topic, envelope_bytes) {
            Ok(_) => info!(node_id = %self.node_id, "Published NodeAnnouncement"),
            Err(e) => {
                // Bump counters for accurate stats (spec 10 §9.2) but
                // do not fire the `publish_failed_insufficient_peers`
                // alert from here — NodeAnnouncement is the periodic
                // self-advertisement, and a failure during the first
                // ~30s of operation (before any peer connects) is
                // structurally expected. The gossip-rx publish path
                // (application data) is where the alert matters.
                self.publish_failure_counters.record(&e);
                debug!(error = %e, "Failed to publish NodeAnnouncement (no peers yet?)");
            }
        }
    }

    /// Publish this node's Hot Topics digest on the `/network` topic (spec 3
    /// §3.9). A no-op when `[hot_topics] enabled`/`mesh_enabled` is false or
    /// this node has nothing to report for the recent buckets.
    fn publish_hot_topics_digest(&mut self) {
        let node_address =
            crate::crypto::pubkey_to_address(&self.signing_key.verifying_key())
                .unwrap_or_default();
        let Some(bytes) = self.hot_topics.build_and_sign_digest(
            &self.hot_topics_keypair,
            &node_address,
            hot_topics::now_ms(),
        ) else {
            return;
        };
        let bytes_len = bytes.len() as u64;
        let topic = libp2p::gossipsub::IdentTopic::new(gossip::topic_network(
            self.topics.network_id(),
        ));
        match self.swarm.behaviour_mut().gossipsub.publish(topic, bytes) {
            Ok(_) => {
                self.counters.add_bytes_out(bytes_len);
                debug!(bytes = bytes_len, "Published HotTopicsDigest");
            }
            Err(e) => {
                self.publish_failure_counters.record(&e);
                debug!(error = %e, "Failed to publish HotTopicsDigest (no peers yet?)");
            }
        }
    }

    /// Validate an incoming presence-gossip record (spec 13 §10.3)
    /// and either cache + accept it, or reject so libp2p suppresses
    /// the mesh relay AND penalizes the relay peer's gossipsub score.
    ///
    /// Validation is async (Ed25519 verify + cache `RwLock::write`),
    /// so it runs on a spawned task. The task sends the outcome over
    /// `presence_validation_tx`; the swarm event loop in [`Self::run`]
    /// drains that channel and calls
    /// `gossipsub.report_message_validation_result` with the
    /// translated `MessageAcceptance`. This honours spec 13 §10.3's
    /// "Rejected records get dropped at the gossipsub layer and are
    /// never relayed" — the `.validate_messages()` flag set in
    /// [`super::behaviour::build_swarm`] holds relay until our report.
    fn handle_presence_message(
        &mut self,
        propagation_source: PeerId,
        message_id: libp2p::gossipsub::MessageId,
        data: Vec<u8>,
    ) {
        let Some(mgr) = self.presence_manager.clone() else {
            // Topic-hash match but no manager — shouldn't happen
            // because the dispatch is gated on `presence_topic_hash`
            // which is `None` iff the manager is `None`. Drop silently.
            return;
        };
        let Some(tx) = self.presence_validation_tx.clone() else {
            // Same invariant: tx is `None` iff manager is `None`.
            return;
        };
        // Track inbound bytes for parity with the standard gossip path.
        self.counters.add_bytes_in(data.len() as u64);
        self.counters.inc_messages_received();
        // Bound concurrent verifies (audit 2026-06-07 W5). If we're already at
        // the cap, report `Ignore` (gossipsub stops holding relay for us) and
        // drop this record unverified rather than spawning an unbounded task.
        let permit = match self.presence_verify_sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                let _ = tx.send(PresenceValidationOutcome {
                    message_id,
                    propagation_source,
                    acceptance: libp2p::gossipsub::MessageAcceptance::Ignore,
                });
                return;
            }
        };
        let counters = self.counters.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when the verify task finishes
            let acceptance = match mgr
                .handle_gossip_message(propagation_source, &data)
                .await
            {
                presence::ValidationOutcome::Accepted => {
                    counters.inc_messages_stored();
                    debug!(
                        msg_id = %message_id,
                        source = %propagation_source,
                        "presence record accepted"
                    );
                    libp2p::gossipsub::MessageAcceptance::Accept
                }
                presence::ValidationOutcome::Rejected(err) => {
                    counters.inc_failed_validations();
                    debug!(
                        msg_id = %message_id,
                        source = %propagation_source,
                        error = %err,
                        "presence record rejected"
                    );
                    libp2p::gossipsub::MessageAcceptance::Reject
                }
            };
            // Send outcome back to the swarm loop. If the receiver is
            // gone we're shutting down — silently drop. (Unbounded
            // channel: bound is the cap of in-flight Ed25519 verifies,
            // which is bounded by the gossipsub mesh fanout × peer
            // rate caps, not by us.)
            let _ = tx.send(PresenceValidationOutcome {
                message_id,
                propagation_source,
                acceptance,
            });
        });
    }

    /// Build and publish the local node's presence record (spec 13
    /// §10.5). Called from the rebroadcast timer in `run` and once
    /// when the mesh reaches ≥ 1 connected peer for the first time.
    /// Returns `true` iff the publish succeeded; the caller uses this
    /// to decide whether to set `presence_initial_broadcast_done` —
    /// keeping the door open for a retry on the next
    /// gossipsub::Event::Subscribed if this attempt fired before the
    /// remote peer's GRAFT exchange. Returns silently (with `true`)
    /// when the manager is absent or non-broadcasting; nothing to
    /// retry there.
    fn publish_presence_self_record(&mut self) -> bool {
        let Some(mgr) = self.presence_manager.as_ref() else {
            return true;
        };
        if !mgr.broadcasting() {
            return true;
        }
        let bytes = match mgr.build_self_record() {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "presence: failed to build self-record");
                return false;
            }
        };
        let topic = gossip::topic_presence(mgr.network_id());
        let topic_obj = libp2p::gossipsub::IdentTopic::new(&topic);
        let topic_hash = topic_obj.hash();
        // Pre-flight subscriber check (0.48.5). Presence is opt-in per
        // node; a peer with presence disabled never subscribes to this
        // topic. Publishing anyway returns NoPeersSubscribedToTopic,
        // which — before this guard — went through `report_publish_failure`
        // (error! log + the publish_failed_insufficient_peers alert + the
        // shared no_peers_subscribed counter), producing a steady drip of
        // false-positive errors on any node whose only peer has presence
        // off. Skipping the publish when nobody is subscribed makes the
        // common case a quiet no-op. We leave `presence_initial_broadcast_done`
        // unset (return false) so the broadcast still fires the moment a
        // presence-enabled peer actually subscribes (handled in the
        // gossipsub `Subscribed` event for our topic). Distinct from the
        // B4 case: there peers ARE subscribed but the mesh won't graft —
        // here there is genuinely no audience, so there is nothing to fix
        // and nothing worth alerting on.
        let subscribers = self
            .swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .filter(|(_, topics)| topics.iter().any(|t| **t == topic_hash))
            .count();
        if subscribers == 0 {
            debug!(
                topic = %topic,
                "presence: no peer subscribed to the presence topic — \
                 skipping broadcast (will fire when one subscribes)"
            );
            return false;
        }
        match self.swarm.behaviour_mut().gossipsub.publish(topic_obj, bytes) {
            Ok(_) => {
                debug!(topic = %topic, "presence: published self-record");
                true
            }
            Err(e) => {
                self.report_publish_failure(&topic, &e);
                false
            }
        }
    }

    /// Fire the one-shot mesh-stabilization broadcast (spec 13 §10.5)
    /// the first time we have ≥ 1 connected peer after boot. The
    /// steady-state publish loop in `run` handles all subsequent
    /// broadcasts.
    ///
    /// Earlier drafts of this gated on ≥ 3 peers to "wait for the
    /// mesh to stabilize" — but that's a death sentence on small
    /// testnets / private deployments where the connected count
    /// never reaches 3. With threshold = 1, the moment we form ANY
    /// peer connection we publish, which is what gossipsub needs
    /// anyway (publishing to an empty mesh returns InsufficientPeers
    /// and gets nowhere). Larger meshes still re-broadcast on the
    /// steady-state cadence; the initial broadcast just stops being
    /// the bottleneck on small networks.
    fn maybe_publish_initial_presence(&mut self) {
        if self.presence_initial_broadcast_done {
            return;
        }
        let Some(mgr) = self.presence_manager.as_ref() else {
            return;
        };
        if !mgr.broadcasting() {
            return;
        }
        let connected = self.swarm.connected_peers().count();
        if connected < 1 {
            return;
        }
        debug!(connected, "presence: peer connected — firing initial broadcast");
        // Only mark "done" if the publish succeeded. A
        // `NoPeersSubscribedToTopic` error means we fired before the
        // gossipsub subscription handshake completed; leaving the
        // flag false lets us retry on the next
        // gossipsub::Event::Subscribed for our topic.
        if self.publish_presence_self_record() {
            self.presence_initial_broadcast_done = true;
        }
    }

    /// Per-peer non-presence gossip rate limit (audit final pre-mainnet
    /// W10). Fixed-window counter, checked BEFORE `handle_gossip_message`
    /// runs so a flooding peer never pays the Keccak/Ed25519/storage cost.
    /// Returns `true` if the message may proceed to full validation.
    fn check_gossip_rate_limit(&mut self, peer: PeerId) -> bool {
        let now = Instant::now();
        match self.gossip_rate_limiter.get_mut(&peer) {
            Some(window) => {
                window.check_and_record(now, GOSSIP_RATE_LIMIT_PER_WINDOW, GOSSIP_RATE_WINDOW)
            }
            None => {
                // New peer — apply the soft cap (Sybil defense, mirrors
                // `PresenceRateLimiter::check_and_record`).
                if self.gossip_rate_limiter.len() >= GOSSIP_RATE_LIMITER_SOFT_CAP {
                    return false;
                }
                self.gossip_rate_limiter.insert(
                    peer,
                    GossipRateWindow {
                        window_start: now,
                        count: 1,
                    },
                );
                true
            }
        }
    }

    /// Drop stale entries from `gossip_rate_limiter` / `gossip_app_score`
    /// so the maps don't grow unboundedly under peer churn (audit final
    /// pre-mainnet W10). Called from the existing 30s `mesh_stats_interval`
    /// tick — see `run`.
    fn prune_gossip_rate_state(&mut self) {
        let now = Instant::now();
        self.gossip_rate_limiter
            .retain(|_, w| now.duration_since(w.window_start) < GOSSIP_RATE_WINDOW * 4);
        // Staleness-based, not value-based (Security Audit, W10
        // follow-up) — see the field doc on `gossip_app_score` for why a
        // value-only (`score != 0`) prune left an exploitable gap.
        self.gossip_app_score
            .retain(|_, e| now.duration_since(e.last_touched) < GOSSIP_APP_SCORE_MAX_IDLE);
        // l2-node 0.137.0, same Sybil-unbounded-growth shape closed
        // above, applied to the newer reconcile-staleness map (security-
        // audit finding, 2026-09-30, round 1).
        self.peer_reconcile_health
            .retain(|_, h| now.duration_since(h.last_touched) < PEER_RECONCILE_HEALTH_MAX_IDLE);
    }

    /// Update a peer's tracked P5 app-score by `delta` (clamped to
    /// [`GOSSIP_APP_SCORE_FLOOR`], `0`) and push the new value to
    /// gossipsub via `set_application_score` (audit final pre-mainnet
    /// W10). `delta` is negative for invalid messages, positive for
    /// accepted ones — see `INVALID_MESSAGE_SCORE_PENALTY`/
    /// `VALID_MESSAGE_SCORE_RECOVERY`.
    fn adjust_gossip_app_score(&mut self, peer: PeerId, delta: i64) {
        let now = Instant::now();
        let entry = self
            .gossip_app_score
            .entry(peer)
            .or_insert(GossipAppScoreEntry {
                score: 0,
                last_touched: now,
            });
        entry.score = clamp_gossip_app_score(entry.score, delta, GOSSIP_APP_SCORE_FLOOR);
        entry.last_touched = now;
        let new_score = entry.score as f64;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .set_application_score(&peer, new_score);
    }

    /// Handle a received GossipSub message through the full validation pipeline.
    /// Process a gossip message and return the gossipsub validation verdict
    /// (audit 2026-06-07 W6). Structurally/cryptographically invalid envelopes
    /// → `Reject` (gossipsub penalizes the source peer + won't propagate);
    /// valid-but-unaccepted-here (policy/authz/dup/unproven-wallet) → `Ignore`
    /// (we don't propagate, but don't penalize an honest relay); accepted →
    /// `Accept` (propagate across the mesh).
    ///
    /// Also drives the P5 (app-specific) gossipsub peer score (audit final
    /// pre-mainnet W10): `Invalid` — the only classification here that
    /// represents genuine attacker-grade badness — penalizes the source
    /// peer's tracked score; `Accepted` nudges it back toward 0. See
    /// `adjust_gossip_app_score` and the `with_peer_score` call in
    /// `behaviour.rs`.
    fn handle_gossip_message(
        &mut self,
        propagation_source: PeerId,
        data: &[u8],
    ) -> libp2p::gossipsub::MessageAcceptance {
        // Track incoming bytes and messages for dashboard metrics
        self.counters.add_bytes_in(data.len() as u64);
        self.counters.inc_messages_received();

        let result = self.router.process_gossip_message(data);
        // The gossipsub verdict is a pure function of the router result
        // (`gossip_acceptance_for`, unit-tested); the arms below only add
        // logging/metrics/side effects.
        let verdict = gossip_acceptance_for(&result);
        match result {
            RouteResult::Accepted {
                msg_id,
                msg_type,
                raw_bytes,
                author,
                bot_commands_changed,
                key_status,
                erased_on_arrival,
            } => {
                if erased_on_arrival {
                    // N7 (l2-node 0.151.0): storing it applied a pending GDPR
                    // deletion request — it is kept hidden: no relay (the
                    // verdict is Ignore), no local push, no notification.
                    debug!(msg_id = %hex::encode(msg_id), "Gossip message erased on arrival by a pending deletion request");
                    return verdict;
                }
                if key_status == Some(crate::messages::router::KeyStatus::AlreadyPresent) {
                    // Nothing was stored (the slot already held a wrap): no
                    // stats, no local push, no relay (round-4 audit W1b).
                    debug!(msg_id = %hex::encode(msg_id), "Key wrap for an already-filled slot from gossip; ignored");
                    return verdict;
                }
                debug!(
                    msg_id = %hex::encode(msg_id),
                    msg_type = ?msg_type,
                    "Message accepted from gossip"
                );

                self.counters.inc_messages_stored();
                self.adjust_gossip_app_score(propagation_source, VALID_MESSAGE_SCORE_RECOVERY);

                // Broadened identity-sync trigger (design doc: "Closing the
                // Identity-Sync Coverage Gap") — closes the gap where a
                // wallet that never personally authenticates to THIS node
                // (only ever seen via gossip-relayed messages) could never
                // trigger a backfill here at all, leaving it permanently
                // dependent on a single live gossip delivery of its
                // ProfileUpdate/Follow/Unfollow never being missed. Live
                // gossip only — `process_synced_message` (the sync/backfill
                // paths) never reaches `handle_gossip_message`, so a synced
                // message can't re-trigger more syncing.
                //
                // `observed_trigger_budget` gates this BEFORE the storage
                // read (security-audit finding): live gossip has no PoW
                // gate on this node (`pow: None` for the gossip router) and
                // no per-wallet rate limit that bites a flood of DISTINCT
                // fresh keypairs, so without a budget an attacker could
                // force `FANOUT` (3) outbound requests to random peers per
                // published message, network-wide, at zero cost — see
                // `IdentityResyncConfig::max_observed_triggers_per_interval`'s
                // doc comment for the full threat model. Checked first
                // (cheapest) so an exhausted budget also skips the
                // `identity_looks_incomplete` storage read, not just the
                // pull itself.
                //
                // LOW-3 (both audits, explicitly deprioritized as "not a
                // security issue" — recorded here rather than silently
                // dropped): this still costs one extra `USERS` CF read per
                // gossip-accepted message of a triggering type while the
                // budget isn't exhausted and the wallet isn't already
                // deduped, on top of the reads `update_indexes` already does
                // earlier in this path. Deferred: the budget already bounds
                // the worst case to `max_observed_triggers_per_interval`
                // *pulls* per tick, and the extra read itself is a bounded
                // local RocksDB point lookup, not a network operation — not
                // worth the added complexity of threading a cached "already
                // looked" flag through `handle_gossip_message` pre-mainnet.
                //
                // The `!self.identity_sync_triggered.contains(&author)` guard
                // (re-audit finding, both Code and Security audits
                // independently): `maybe_trigger_identity_sync` silently
                // no-ops for an already-deduped wallet, so without this check
                // the budget was spent on triggers that dispatch zero
                // requests. A single wallet whose USERS row can never
                // converge (e.g. a bare row created by a Follow/
                // DeviceDelegation side effect, per `identity_sync.rs`'s
                // "looks incomplete" doc comment) would pin the budget at 0
                // via ordinary chat traffic well within the existing
                // per-wallet rate limit — silently disabling the broadened
                // trigger for every OTHER wallet for the rest of the
                // interval. Checking dedup here (a cheap hash lookup) instead
                // of only inside `maybe_trigger_identity_sync` also means the
                // budget is only ever spent on a trigger that will actually
                // fire.
                self.observe_author_for_identity_pull(&author, msg_type as u8, false);

                // Feed to notification engine for mention detection (fire-and-forget)
                if let Some(ref engine) = self.notification_engine {
                    let engine = engine.clone();
                    // Live gossip only. The sync paths call
                    // `process_synced_message`, which never yields this field —
                    // identity-sync bypasses rate limiting by design, so
                    // broadcasting from it would be an unbounded fan-out during
                    // backfill that the ProfileUpdate rate limit cannot bound.
                    let bot_wallet = bot_commands_changed.clone();
                    tokio::spawn(async move {
                        if let Ok(envelope) = rmp_serde::from_slice::<Envelope>(&raw_bytes) {
                            engine.process(&envelope).await;
                        }
                        if let Some(wallet) = bot_wallet {
                            engine.broadcast_bot_commands_changed(&wallet).await;
                        }
                    });
                }

                verdict
            }
            RouteResult::Duplicate => {
                debug!("Duplicate message from gossip, skipping");
                // Already have it — valid, but no need to re-propagate from us.
                verdict
            }
            RouteResult::Invalid(reason) => {
                self.counters.inc_failed_validations();
                warn!(reason = %reason, "Invalid message from gossip — rejecting (penalize peer)");
                self.adjust_gossip_app_score(propagation_source, -INVALID_MESSAGE_SCORE_PENALTY);
                verdict
            }
            RouteResult::Rejected(reason) => {
                self.counters.inc_failed_validations();
                // "on-chain registration required" means THIS node's local chain-scan
                // cache doesn't have the author's USERS record yet, even though the
                // envelope passed signature verification and (for channel actions)
                // channel-ACL authorization. That combination almost always means the
                // author IS legitimately registered and this node's scanner is lagging
                // or gapped — a real moderation-enforcement risk (e.g. a ChannelBan
                // silently never applying on this node) that debug!-level logging made
                // invisible outside an explicit RUST_LOG=debug session. Surface it.
                if reason.contains(crate::messages::router::REGISTRATION_REQUIRED_REASON) {
                    warn!(
                        reason = %reason,
                        "Message rejected: local chain-scan state may be lagging the network"
                    );
                } else {
                    debug!(reason = %reason, "Message not accepted locally — ignoring (no penalty)");
                }
                verdict
            }
            RouteResult::PowRequired { address } => {
                debug!(address = %address, "PoW required for gossip message (ignoring)");
                verdict
            }
            // Key-epoch arbitration (l2-node 0.143.0): a losing or post-
            // finality commitment is a POLICY outcome, not invalidity — an
            // honest concurrent establisher produces it. Don't relay it from
            // us, don't penalize the peer.
            RouteResult::KeyConflict(info) => {
                debug!(
                    channel_id = info.channel_id,
                    epoch = info.epoch,
                    "Key envelope lost epoch arbitration — ignoring (no penalty)"
                );
                verdict
            }
        }
    }
}

/// Gossipsub verdict for a router result received over gossip:
/// `Accepted` → `Accept` (relay) — except an already-present key wrap
/// (not stored, not relayed) → `Ignore`; `Invalid` → `Reject` (penalize the source
/// — no honest peer relays it); every POLICY outcome → `Ignore` (don't relay
/// from us, don't penalize): `Duplicate`, `Rejected`, `PowRequired` and —
/// l2-node 0.143.0 — `KeyConflict` (a losing-but-honest concurrent key
/// establisher's envelope).
pub(crate) fn gossip_acceptance_for(result: &RouteResult) -> libp2p::gossipsub::MessageAcceptance {
    use libp2p::gossipsub::MessageAcceptance;
    match result {
        // A key wrap for an already-filled slot was not stored: relaying it
        // would only amplify replays (round-4 audit W1b).
        RouteResult::Accepted {
            key_status: Some(crate::messages::router::KeyStatus::AlreadyPresent),
            ..
        } => MessageAcceptance::Ignore,
        RouteResult::Accepted { erased_on_arrival: true, .. } => MessageAcceptance::Ignore,
        RouteResult::Accepted { .. } => MessageAcceptance::Accept,
        RouteResult::Invalid(_) => MessageAcceptance::Reject,
        RouteResult::Duplicate
        | RouteResult::Rejected(_)
        | RouteResult::PowRequired { .. }
        | RouteResult::KeyConflict(_) => MessageAcceptance::Ignore,
    }
}

#[cfg(test)]
mod gossip_flood_protection_tests {
    //! Audit final pre-mainnet W10. Covers the pure logic factored out of
    //! `NetworkService::check_gossip_rate_limit` / `adjust_gossip_app_score`
    //! — see the note on `GossipRateWindow::check_and_record` for why the
    //! swarm-event-handler methods themselves aren't tested directly here.
    use super::*;

    #[test]
    fn rate_window_allows_up_to_the_limit_then_blocks() {
        let start = Instant::now();
        let mut window = GossipRateWindow {
            window_start: start,
            count: 0,
        };
        for _ in 0..GOSSIP_RATE_LIMIT_PER_WINDOW {
            assert!(window.check_and_record(start, GOSSIP_RATE_LIMIT_PER_WINDOW, GOSSIP_RATE_WINDOW));
        }
        assert!(!window.check_and_record(start, GOSSIP_RATE_LIMIT_PER_WINDOW, GOSSIP_RATE_WINDOW));
    }

    #[test]
    fn rate_window_resets_after_the_window_elapses() {
        let start = Instant::now();
        let mut window = GossipRateWindow {
            window_start: start,
            count: GOSSIP_RATE_LIMIT_PER_WINDOW,
        };
        assert!(!window.check_and_record(start, GOSSIP_RATE_LIMIT_PER_WINDOW, GOSSIP_RATE_WINDOW));
        let after = start + GOSSIP_RATE_WINDOW;
        assert!(window.check_and_record(after, GOSSIP_RATE_LIMIT_PER_WINDOW, GOSSIP_RATE_WINDOW));
        assert_eq!(window.count, 1);
        assert_eq!(window.window_start, after);
    }

    #[test]
    fn app_score_penalty_reaches_graylist_equivalent_within_a_handful_of_invalid_messages() {
        // Default gossipsub `app_specific_weight` is 10.0 and
        // `graylist_threshold` is -80.0 (library defaults, see
        // behaviour.rs). The P5 contribution alone crosses graylist once
        // the tracked score reaches -8, so this should take only a few
        // `INVALID_MESSAGE_SCORE_PENALTY`-sized steps, not dozens.
        let mut score = 0i64;
        let mut steps = 0;
        while score > -8 && steps < 20 {
            score = clamp_gossip_app_score(score, -INVALID_MESSAGE_SCORE_PENALTY, GOSSIP_APP_SCORE_FLOOR);
            steps += 1;
        }
        assert!(steps <= 10, "took {steps} invalid messages to reach graylist-equivalent");
    }

    #[test]
    fn app_score_recovery_is_slower_than_penalty_and_cannot_exceed_zero() {
        let penalized = clamp_gossip_app_score(0, -INVALID_MESSAGE_SCORE_PENALTY, GOSSIP_APP_SCORE_FLOOR);
        let recovered = clamp_gossip_app_score(penalized, VALID_MESSAGE_SCORE_RECOVERY, GOSSIP_APP_SCORE_FLOOR);
        // One bad message followed by one good message must not fully
        // cancel out — otherwise an attacker can interleave 1 good : 1
        // bad forever and stay at score 0 indefinitely.
        assert!(recovered < 0, "recovery must not fully offset a penalty in one step");
        assert_eq!(
            clamp_gossip_app_score(0, VALID_MESSAGE_SCORE_RECOVERY, GOSSIP_APP_SCORE_FLOOR),
            0,
            "recovery must not push the score above 0"
        );
    }

    #[test]
    fn app_score_floor_bounds_a_sustained_flood() {
        let mut score = 0i64;
        for _ in 0..1000 {
            score = clamp_gossip_app_score(score, -INVALID_MESSAGE_SCORE_PENALTY, GOSSIP_APP_SCORE_FLOOR);
        }
        assert_eq!(score, GOSSIP_APP_SCORE_FLOOR);
    }
}

#[cfg(test)]
mod dm_reaper_tests {
    //! Audit final pre-mainnet W11. Covers the pure planning logic factored
    //! out of `NetworkService::reap_dm_msg_shaped_cf`/`reap_dm_conversations`
    //! — see the note on `plan_dm_msg_shaped_reap` for why the `&mut self`
    //! reaper methods themselves aren't tested directly here.
    use super::*;

    fn dm_msg_row(conversation_id: [u8; 32], ts: u64, msg_id: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        (schema::encode_dm_msg_key(&conversation_id, ts, &msg_id), Vec::new())
    }

    #[test]
    fn plan_dm_msg_shaped_reap_deletes_only_expired_rows() {
        let conv = [1u8; 32];
        let rows = vec![
            dm_msg_row(conv, 100, [1u8; 32]), // expired
            dm_msg_row(conv, 200, [2u8; 32]), // not expired
            dm_msg_row(conv, 50, [3u8; 32]),  // expired
        ];
        let (to_delete, next_cursor) = plan_dm_msg_shaped_reap(&rows, 150, 100);
        assert_eq!(to_delete.len(), 2);
        assert!(to_delete.contains(&rows[0].0));
        assert!(to_delete.contains(&rows[2].0));
        assert!(!to_delete.contains(&rows[1].0));
        assert!(next_cursor.is_some());
    }

    #[test]
    fn plan_dm_msg_shaped_reap_respects_batch_limit() {
        let conv = [1u8; 32];
        let rows: Vec<_> = (0..10)
            .map(|i| dm_msg_row(conv, 0, [i as u8; 32])) // all expired (ts=0)
            .collect();
        let (to_delete, next_cursor) = plan_dm_msg_shaped_reap(&rows, 1000, 3);
        assert_eq!(to_delete.len(), 3);
        // Code Audit follow-up: the cursor must resume from just past the
        // LAST EXAMINED row (index 2, the 3rd), never past an unexamined
        // one (index 3) — an earlier draft set `last_key` before the
        // batch-limit break, which silently orphaned row 3 from every
        // future sweep regardless of how expired it later became.
        let expected_cursor = {
            let mut c = rows[2].0.clone();
            c.push(0);
            c
        };
        assert_eq!(next_cursor, Some(expected_cursor));
    }

    #[test]
    fn plan_dm_msg_shaped_reap_empty_batch_returns_none_cursor() {
        let (to_delete, next_cursor) = plan_dm_msg_shaped_reap(&[], 1000, 100);
        assert!(to_delete.is_empty());
        assert!(next_cursor.is_none());
    }

    #[test]
    fn plan_dm_msg_shaped_reap_cursor_advances_past_last_examined_row_even_if_nothing_deleted() {
        let conv = [1u8; 32];
        let rows = vec![dm_msg_row(conv, 999_999, [9u8; 32])]; // not expired
        let (to_delete, next_cursor) = plan_dm_msg_shaped_reap(&rows, 100, 100);
        assert!(to_delete.is_empty());
        let cursor = next_cursor.expect("cursor must still advance to make forward progress");
        assert!(cursor > rows[0].0, "cursor must sort strictly after the last examined row");
    }

    fn dm_conv_row(wallet: &[u8], last_activity_ts: u64, conversation_id: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        (
            schema::encode_dm_conversation_key(wallet, last_activity_ts, &conversation_id),
            Vec::new(),
        )
    }

    #[test]
    fn plan_dm_conversations_reap_handles_variable_length_wallet_prefix() {
        // A real resolved wallet is 62 bytes; an attacker-controlled
        // `payload.recipient` string can be shorter (only bounded at 70 by
        // MAX_KLEVER_ADDRESS_LEN). Both must be parsed correctly — this is
        // exactly the bug an earlier draft of this fix had (hardcoded 62).
        let short_wallet = b"klv1short";
        let full_wallet = [b'a'; 62];
        let rows = vec![
            dm_conv_row(short_wallet, 100, [1u8; 32]), // expired
            dm_conv_row(&full_wallet, 100, [2u8; 32]), // expired
        ];
        let (to_delete, _) = plan_dm_conversations_reap(&rows, 150, 100);
        assert_eq!(to_delete.len(), 2, "both variable-length wallet prefixes must be reaped correctly");
    }

    #[test]
    fn plan_dm_conversations_reap_respects_negated_timestamp_ordering() {
        let wallet = b"klv1abc";
        let rows = vec![
            dm_conv_row(wallet, 200, [1u8; 32]), // not expired
            dm_conv_row(wallet, 50, [2u8; 32]),  // expired
        ];
        let (to_delete, _) = plan_dm_conversations_reap(&rows, 150, 100);
        assert_eq!(to_delete.len(), 1);
        assert_eq!(to_delete[0], rows[1].0);
    }

    #[test]
    fn plan_dm_conversations_reap_empty_batch_returns_none_cursor() {
        let (to_delete, next_cursor) = plan_dm_conversations_reap(&[], 1000, 100);
        assert!(to_delete.is_empty());
        assert!(next_cursor.is_none());
    }
}

#[cfg(test)]
mod identity_staleness_sweep_tests {
    //! Design doc "Closing the Identity-Sync Coverage Gap" §2 — pure
    //! planning logic factored out of `NetworkService::sweep_identity_staleness`.
    //! See `plan_dm_msg_shaped_reap`'s doc note (`dm_reaper_tests` above) for
    //! why the `&mut self` sweep method itself isn't tested directly here —
    //! same reasoning: no existing test in this file constructs a live
    //! `NetworkService` (it owns a real libp2p `Swarm`), so every test here
    //! targets the pure decision logic a live sweep would use.
    use super::*;

    fn users_row(wallet: &[u8], incomplete: bool) -> (Vec<u8>, Vec<u8>) {
        let json = if incomplete {
            serde_json::json!({ "address": String::from_utf8_lossy(wallet) })
        } else {
            serde_json::json!({
                "address": String::from_utf8_lossy(wallet),
                "profile_updated_at": 1_700_000_000_000u64,
            })
        };
        (wallet.to_vec(), serde_json::to_vec(&json).unwrap())
    }

    #[test]
    fn plan_identity_staleness_sweep_selects_only_incomplete_rows() {
        let rows = vec![
            users_row(b"klv1aaa", true),
            users_row(b"klv1bbb", false),
            users_row(b"klv1ccc", true),
        ];
        let (mut candidates, next_cursor) = plan_identity_staleness_sweep(&rows, 10);
        // Selection order is randomized (C1 fix — see the "caps candidates"
        // test below), so compare as a set.
        candidates.sort();
        assert_eq!(candidates, vec!["klv1aaa".to_string(), "klv1ccc".to_string()]);
        assert!(next_cursor.is_some());
    }

    #[test]
    fn plan_identity_staleness_sweep_excludes_a_row_with_no_display_name_but_a_timestamp() {
        // The negative case the requirements are most worried about: a
        // wallet that legitimately has no display name (but DOES have
        // profile_updated_at) must never show up as a candidate. `rows` is
        // fixed input and this function is pure, so one call over it is
        // representative of every call over it — this does not need
        // (and does not claim) to hold across a running sweep's state.
        //
        // The key must be alphanumeric (`is_plausible_subject`, LOW-1) so
        // this test actually discriminates on `profile_looks_incomplete_json`
        // rather than passing for the unrelated reason that a hyphenated key
        // would be rejected regardless of that check (re-audit finding).
        let rows = vec![users_row(b"klv1hasnonamebychoice", false)];
        let (candidates, _) = plan_identity_staleness_sweep(&rows, 10);
        assert!(candidates.is_empty());
    }

    #[test]
    fn plan_identity_staleness_sweep_caps_candidates_at_max_retriggers_but_still_advances_cursor_past_whole_batch() {
        // 5 incomplete rows in the batch, but max_retriggers=2 — exactly the
        // "request cost is independent of scan cost" property from the
        // design doc: the cursor must still land past the LAST row in the
        // batch (row 5), not just past the 2nd candidate, so an
        // incomplete-heavy region can never stall scan progress for
        // everything after it.
        let rows: Vec<_> = (0..5)
            .map(|i| users_row(format!("klv1{i}").as_bytes(), true))
            .collect();
        let (candidates, next_cursor) = plan_identity_staleness_sweep(&rows, 2);
        assert_eq!(candidates.len(), 2);
        let expected_cursor = {
            let mut c = rows[4].0.clone();
            c.push(0);
            c
        };
        assert_eq!(next_cursor, Some(expected_cursor));
    }

    #[test]
    fn plan_identity_staleness_sweep_empty_batch_returns_none_cursor() {
        let (candidates, next_cursor) = plan_identity_staleness_sweep(&[], 10);
        assert!(candidates.is_empty());
        assert!(next_cursor.is_none());
    }

    #[test]
    fn plan_identity_staleness_sweep_zero_max_retriggers_still_advances_cursor() {
        // A caller passing max_retriggers=0 (e.g. config edge case) must
        // still make scan progress — this is what proves scan and request
        // cost are genuinely decoupled, not just "capped low".
        let rows = vec![users_row(b"klv1aaa", true), users_row(b"klv1bbb", true)];
        let (candidates, next_cursor) = plan_identity_staleness_sweep(&rows, 0);
        assert!(candidates.is_empty());
        let expected_cursor = {
            let mut c = rows[1].0.clone();
            c.push(0);
            c
        };
        assert_eq!(next_cursor, Some(expected_cursor));
    }
}

#[cfg(test)]
mod channel_backfill_due_tests {
    //! Fix for a permanent-partial-sync bug (found 2026-09-30) — pure
    //! decision logic factored out of `NetworkService::maybe_trigger_backfill`.
    //! See `identity_staleness_sweep_tests`'s doc note for why the `&mut
    //! self` trigger itself isn't tested directly here.
    use super::*;

    #[test]
    fn never_completed_is_always_due_regardless_of_interval() {
        assert!(channel_backfill_due(None, 1_000_000, 6));
        assert!(channel_backfill_due(None, 1_000_000, 0));
    }

    #[test]
    fn recently_completed_is_not_due() {
        let now = 1_000_000u64;
        let completed = now - 3600; // 1 hour ago
        assert!(!channel_backfill_due(Some(completed), now, 6));
    }

    #[test]
    fn completed_longer_ago_than_the_interval_is_due_again() {
        let now = 1_000_000u64;
        let completed = now - 7 * 3600; // 7 hours ago
        assert!(channel_backfill_due(Some(completed), now, 6));
    }

    #[test]
    fn exactly_at_the_interval_boundary_is_due() {
        let now = 1_000_000u64;
        let completed = now - 6 * 3600;
        assert!(channel_backfill_due(Some(completed), now, 6));
    }

    /// `catchup_interval_hours = 0` means "never re-check a channel that
    /// already completed" — but must NOT be confused with "never due at
    /// all", which would resurrect the any-row-proxy bug for the
    /// never-completed case.
    #[test]
    fn zero_interval_disables_recheck_of_completed_channels_only() {
        let now = 1_000_000u64;
        assert!(!channel_backfill_due(Some(now - 1_000_000), now, 0));
        assert!(channel_backfill_due(None, now, 0));
    }

    /// A completion timestamp from the future (clock skew, or a
    /// backwards-adjusted system clock) must not underflow and must not be
    /// treated as "ancient" — `saturating_sub` keeps this at 0 elapsed.
    #[test]
    fn completion_timestamp_in_the_future_does_not_underflow() {
        let now = 1_000u64;
        assert!(!channel_backfill_due(Some(now + 1_000_000), now, 6));
    }
}

#[cfg(test)]
mod reconcile_comparison_tests {
    //! Peer-completeness comparison + staleness tracking (l2-node
    //! 0.137.0) — pure decision logic factored out of
    //! `NetworkService::finalize_reconcile_comparison`/
    //! `maybe_trigger_backfill`. See `channel_backfill_due_tests`'s doc
    //! note for why the `&mut self` methods themselves aren't tested
    //! directly here.
    use super::*;

    fn fake_peer() -> PeerId {
        let kp = libp2p::identity::Keypair::generate_ed25519();
        kp.public().to_peer_id()
    }

    fn response_with_envelope_count(n: usize) -> reconcile::ReconcileResponse {
        reconcile::ReconcileResponse {
            envelopes: (0..n).map(|_| Vec::new()).collect(),
            ..reconcile::ReconcileResponse::empty(1)
        }
    }

    #[test]
    fn rank_empty_candidates_returns_empty_order() {
        let candidates: Vec<(PeerId, reconcile::ReconcileResponse)> = Vec::new();
        assert_eq!(rank_reconcile_candidates_by_size(&candidates), Vec::<usize>::new());
    }

    #[test]
    fn rank_single_candidate_is_trivially_first() {
        let candidates = vec![(fake_peer(), response_with_envelope_count(5))];
        assert_eq!(rank_reconcile_candidates_by_size(&candidates), vec![0]);
    }

    #[test]
    fn rank_orders_by_envelope_count_descending() {
        let candidates = vec![
            (fake_peer(), response_with_envelope_count(3)),
            (fake_peer(), response_with_envelope_count(107)),
            (fake_peer(), response_with_envelope_count(50)),
        ];
        assert_eq!(rank_reconcile_candidates_by_size(&candidates), vec![1, 2, 0]);
    }

    /// Stable sort: ties keep first-seen order, so the outcome is
    /// deterministic rather than depending on hash/shuffle order.
    #[test]
    fn rank_ties_keep_first_seen_order() {
        let candidates = vec![
            (fake_peer(), response_with_envelope_count(10)),
            (fake_peer(), response_with_envelope_count(10)),
        ];
        assert_eq!(rank_reconcile_candidates_by_size(&candidates), vec![0, 1]);
    }

    /// Security-audit finding (2026-09-30, round 1): staleness scoring
    /// must be driven by VERIFIED trial outcomes, never raw pre-
    /// verification reported counts — a peer padding a huge garbage
    /// count must gain nothing by out-*reporting* an honest peer, only
    /// by out-*delivering* one. `split_reconcile_trial_results` is the
    /// pure core of that: a peer only ever lands in `behind` once it
    /// was actually tried (verified) and failed, and only when a LATER
    /// trial in the same list proved real content existed.
    #[test]
    fn split_no_trials_is_empty() {
        let (competitive, behind) = split_reconcile_trial_results(&[]);
        assert!(competitive.is_empty());
        assert!(behind.is_empty());
    }

    #[test]
    fn split_single_winner_has_no_losers() {
        let winner = fake_peer();
        let (competitive, behind) = split_reconcile_trial_results(&[(winner, true)]);
        assert_eq!(competitive, vec![winner]);
        assert!(behind.is_empty());
    }

    #[test]
    fn split_failed_candidates_before_a_winner_are_behind() {
        let loser1 = fake_peer();
        let loser2 = fake_peer();
        let winner = fake_peer();
        let (competitive, behind) = split_reconcile_trial_results(&[
            (loser1, false),
            (loser2, false),
            (winner, true),
        ]);
        assert_eq!(competitive, vec![winner]);
        assert_eq!(behind, vec![loser1, loser2]);
    }

    /// When every TRIED candidate failed (no winner found at all), the
    /// caller (`finalize_reconcile_comparison`) must not even reach
    /// this — there's no verified evidence anyone was relatively
    /// behind. This test just documents the raw split's own behavior in
    /// that shape (everyone lands in `behind`) so it's clear the
    /// "don't touch health when nobody wins" decision is the CALLER's
    /// responsibility, not something this pure function enforces.
    #[test]
    fn split_with_no_winner_puts_everyone_in_behind() {
        let a = fake_peer();
        let b = fake_peer();
        let (competitive, behind) = split_reconcile_trial_results(&[(a, false), (b, false)]);
        assert!(competitive.is_empty());
        assert_eq!(behind, vec![a, b]);
    }

    #[test]
    fn stale_threshold_crossing() {
        assert!(!is_peer_stale(2, 3), "below threshold must not be stale");
        assert!(is_peer_stale(3, 3), "at threshold must be stale");
        assert!(is_peer_stale(10, 3), "well past threshold must be stale");
    }

    #[test]
    fn zero_threshold_disables_staleness_tracking() {
        assert!(!is_peer_stale(1_000_000, 0));
    }
}

#[cfg(test)]
mod responder_build_slot_tests {
    //! Round-5 C-W1: the node-wide responder build cap refuses only
    //! session-STARTING requests; a continuation page waits (bounded) for a
    //! slot instead of being answered `server_capped`.
    use super::*;
    use tokio::sync::Semaphore;

    fn sems() -> (Arc<Semaphore>, Arc<Semaphore>) {
        (
            Arc::new(Semaphore::new(MAX_CONCURRENT_RESPONDER_BUILDS)),
            Arc::new(Semaphore::new(MAX_CONTINUATION_BUILD_WAITERS)),
        )
    }

    #[test]
    fn busy_slots_refuse_starts_but_let_continuations_wait() {
        let (build, wait) = sems();
        // Free slot: both kinds build now.
        assert!(matches!(pick_build_slot(&build, &wait, false), BuildSlot::Now(_)));
        assert!(matches!(pick_build_slot(&build, &wait, true), BuildSlot::Now(_)));
        // All build slots busy.
        let held: Vec<_> = (0..MAX_CONCURRENT_RESPONDER_BUILDS)
            .map(|_| build.clone().try_acquire_owned().unwrap())
            .collect();
        assert!(matches!(pick_build_slot(&build, &wait, false), BuildSlot::Refuse));
        let mut waiters = Vec::new();
        for _ in 0..MAX_CONTINUATION_BUILD_WAITERS {
            match pick_build_slot(&build, &wait, true) {
                BuildSlot::Wait(w) => waiters.push(w),
                _ => panic!("a continuation must be allowed to wait"),
            }
        }
        // Waiters are bounded too.
        assert!(matches!(pick_build_slot(&build, &wait, true), BuildSlot::Refuse));
        drop(waiters);
        assert!(matches!(pick_build_slot(&build, &wait, true), BuildSlot::Wait(_)));
        drop(held);
    }

    /// Hold every build slot and run `continuation` (the request's own
    /// classification, exactly what the handlers pass to
    /// `responder_build_slot`) through the slot decision.
    fn decide_when_busy(continuation: bool) -> &'static str {
        let (build, wait) = sems();
        let _held: Vec<_> = (0..MAX_CONCURRENT_RESPONDER_BUILDS)
            .map(|_| build.clone().try_acquire_owned().unwrap())
            .collect();
        match pick_build_slot(&build, &wait, continuation) {
            BuildSlot::Now(_) => "now",
            BuildSlot::Wait(_) => "wait",
            BuildSlot::Refuse => "refuse",
        }
    }

    fn reconcile_req(cursor: Option<reconcile::ReconcileCursor>) -> reconcile::ReconcileRequest {
        reconcile::ReconcileRequest {
            channel_id: 7,
            max_age_secs: u64::MAX,
            cursor,
            fingerprint: Vec::new(),
            epoch_root_known: None,
            round: 0,
            meta_cursor: None,
            revision: 0,
        }
    }

    /// Round-6: the reconcile handler's classification. A first page (no
    /// cursor) STARTS a session and is refused `server_capped` when all 8
    /// builds are busy; a cursor-bearing page is a continuation and waits
    /// on the bounded waiter pool.
    #[test]
    fn reconcile_first_page_is_refused_and_cursor_page_waits_when_busy() {
        let first = reconcile_req(None);
        assert!(!first.is_continuation(), "a first page starts a session");
        assert_eq!(decide_when_busy(first.is_continuation()), "refuse");

        let next = reconcile_req(Some(reconcile::ReconcileCursor {
            after_lamport_ts: 42,
            after_msg_id: [3u8; 32],
        }));
        assert!(next.is_continuation(), "a cursor-bearing page continues a session");
        assert_eq!(decide_when_busy(next.is_continuation()), "wait");
    }

    /// Round-6: the private-channel-sync handler's classification
    /// (`PrivateChannelSyncRequest::is_continuation`) through the same
    /// busy-slot decision.
    #[test]
    fn private_sync_first_page_is_refused_and_continuations_wait_when_busy() {
        use private_channel_sync::PrivateChannelSyncCursor;
        use reconcile::MetaCursor;
        let sk = crate::crypto::generate_keypair();
        let mut r = private_channel_sync::sign_request(
            &sk, "testnet", "peer", "klv1w", 7, 1, u64::MAX, None, None,
        );
        r.meta_paging = true;
        assert_eq!(decide_when_busy(r.is_continuation()), "refuse", "first metadata page");
        r.meta_paging = false;
        assert_eq!(decide_when_busy(r.is_continuation()), "refuse", "legacy first page");

        r.meta_cursor = Some(MetaCursor { tier: 1, ts: 1, msg_id: [1; 32] });
        assert_eq!(decide_when_busy(r.is_continuation()), "wait", "metadata cursor");
        r.meta_cursor = None;
        r.meta_done = true;
        assert_eq!(decide_when_busy(r.is_continuation()), "wait", "first chat page after metadata");
        r.meta_done = false;
        r.cursor = Some(PrivateChannelSyncCursor { after_lamport_ts: 1, after_msg_id: [0u8; 32] });
        assert_eq!(decide_when_busy(r.is_continuation()), "wait", "chat cursor");
    }

    #[tokio::test(start_paused = true)]
    async fn a_waiting_continuation_gets_the_next_free_slot() {
        let (build, wait) = sems();
        let held: Vec<_> = (0..MAX_CONCURRENT_RESPONDER_BUILDS)
            .map(|_| build.clone().try_acquire_owned().unwrap())
            .collect();
        let w = wait.clone().try_acquire_owned().unwrap();
        let b2 = build.clone();
        let task = tokio::spawn(async move { wait_for_build_slot(b2, w).await });
        tokio::time::sleep(CONTINUATION_BUILD_SLOT_WAIT / 2).await;
        drop(held); // a build finishes
        let got = task.await.unwrap();
        assert!(got.is_ok(), "the continuation must get the freed slot");
        // Its waiter slot was released.
        assert_eq!(wait.available_permits(), MAX_CONTINUATION_BUILD_WAITERS);
    }

    #[tokio::test(start_paused = true)]
    async fn a_waiting_continuation_times_out_with_its_waiter_slot() {
        let (build, wait) = sems();
        let _held: Vec<_> = (0..MAX_CONCURRENT_RESPONDER_BUILDS)
            .map(|_| build.clone().try_acquire_owned().unwrap())
            .collect();
        let w = wait.clone().try_acquire_owned().unwrap();
        let got = wait_for_build_slot(build.clone(), w).await;
        let waiter = got.expect_err("must time out while every slot stays busy");
        // The waiter slot is still held (it rides along with the capped
        // response), and released when that response is dropped.
        assert_eq!(wait.available_permits(), MAX_CONTINUATION_BUILD_WAITERS - 1);
        drop(waiter);
        assert_eq!(wait.available_permits(), MAX_CONTINUATION_BUILD_WAITERS);
        assert!(CONTINUATION_BUILD_SLOT_WAIT < std::time::Duration::from_secs(45));
    }
}

#[cfg(test)]
mod backfill_throttle_tests {
    //! l2-node 0.141.0: the requester attempt throttle, the IN_SYNC
    //! verdict and `duplicate_is_verified`, exercised through a real
    //! (unconnected) `NetworkService` where the wiring matters, and through
    //! the pure helpers otherwise.
    use super::*;
    use crate::crypto::signing;
    use crate::messages::types::MessageType;
    use tempfile::TempDir;

    const CID: u64 = 7;
    const T0: u64 = 1_700_000_000_000; // ms

    struct W {
        sk: ed25519_dalek::SigningKey,
        addr: String,
    }
    fn wallet() -> W {
        let sk = crate::crypto::generate_keypair();
        let addr = crate::crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        W { sk, addr }
    }

    fn config() -> Config {
        let mut c: Config = toml::from_str(&Config::default_toml()).unwrap();
        c.network.listen_port = 0;
        c.network.enable_mdns = false;
        c
    }

    async fn service() -> (NetworkService, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let config = config();
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let svc = NetworkService::new(
            &config,
            storage.clone(),
            IdentityResolver::new(storage),
            libp2p::identity::Keypair::generate_ed25519(),
            None,
            Arc::new(AtomicU32::new(0)),
            crate::crypto::generate_keypair(),
            "test-node".into(),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(NetworkCounters::new()),
            Arc::new(RwLock::new(None)),
            rx,
            Arc::new(AtomicU64::new(0)),
            Arc::new(RwLock::new(HashSet::new())),
            mesh_stats::PublishFailureCounters::default(),
            mesh_stats::shared_empty(),
            None,
            config.backfill.clone(),
            config.dm.clone(),
            config.identity_resync.clone(),
            config.private_channel_sync.clone(),
        )
        .await
        .unwrap();
        (svc, dir)
    }

    /// A responder node (router + storage) on the same network id.
    fn responder() -> (MessageRouter, Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let r = MessageRouter::new(
            storage.clone(),
            IdentityResolver::new(storage.clone()),
            None,
            config().network_id().to_string(),
            usize::MAX,
            Arc::new(NetworkCounters::new()),
            crate::config::RateLimitsConfig::default(),
        );
        (r, storage, dir)
    }

    fn setup_public_channel(s: &Storage, creator: &str) {
        s.put_cf(
            schema::cf::CHANNELS,
            &CID.to_be_bytes(),
            serde_json::json!({"channel_id": CID, "channel_type": 0, "creator": creator,
                "member_count": 0}).to_string().as_bytes(),
        )
        .unwrap();
        s.put_cf(
            schema::cf::USERS,
            creator.as_bytes(),
            serde_json::json!({"address": creator, "registered_at": 1}).to_string().as_bytes(),
        )
        .unwrap();
    }

    fn chat(w: &W, ts: u64) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct C {
            channel_id: u64,
            content: String,
        }
        let net = config().network_id().to_string();
        let payload = rmp_serde::to_vec_named(&C { channel_id: CID, content: format!("m{ts}") }).unwrap();
        let pk: [u8; 32] = w.sk.verifying_key().to_bytes();
        let msg_id = crate::crypto::compute_msg_id(&net, &pk, &payload, ts);
        let sig = signing::sign_ogmara_message(
            &w.sk,
            &net,
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ChatMessage as u8,
            &msg_id,
            ts,
            &payload,
        );
        rmp_serde::to_vec_named(&Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChatMessage,
            msg_id,
            author: w.addr.clone(),
            timestamp: ts,
            lamport_ts: 0,
            payload,
            signature: sig.to_bytes().to_vec(),
            relay_path: vec![],
        })
        .unwrap()
    }

    fn feed(r: &MessageRouter, raw: &[u8]) {
        let res = r.process_synced_message(raw);
        assert!(matches!(res, RouteResult::Accepted { .. }), "fixture rejected: {res:?}");
    }

    fn page(s: &Storage, cap: usize) -> reconcile::ReconcileResponse {
        let req = reconcile::ReconcileRequest {
            channel_id: CID,
            max_age_secs: u64::MAX,
            cursor: None,
            fingerprint: Vec::new(),
            epoch_root_known: None,
            round: 0,
            meta_cursor: None,
            revision: 0,
        };
        reconcile::build_response(s, &req, cap, T0 / 1000 + 1_000)
    }

    /// Requester `svc` holds messages `0..have`; each responder holds
    /// `0..n` for its own `n`. Returns the responders' first pages.
    fn fixture(svc: &NetworkService, have: u64, responders: &[u64], cap: usize) -> Vec<reconcile::ReconcileResponse> {
        let c = wallet();
        setup_public_channel(&svc.storage, &c.addr);
        let msgs: Vec<Vec<u8>> = (0..10).map(|i| chat(&c, T0 + i)).collect();
        for m in &msgs[..have as usize] {
            feed(&svc.router, m);
        }
        responders
            .iter()
            .map(|&n| {
                let (r, s, d) = responder();
                setup_public_channel(&s, &c.addr);
                for m in &msgs[..n as usize] {
                    feed(&r, m);
                }
                let p = page(&s, cap);
                drop(d);
                p
            })
            .collect()
    }

    fn open_comparison(
        svc: &mut NetworkService,
        candidates: Vec<(PeerId, reconcile::ReconcileResponse)>,
        straggler: bool,
        any_capped: bool,
    ) -> Option<libp2p::request_response::OutboundRequestId> {
        let mut outstanding = HashSet::new();
        let mut straggler_id = None;
        if straggler {
            let id = svc.swarm.behaviour_mut().reconcile.send_request(
                &PeerId::random(),
                reconcile::ReconcileRequest {
                    channel_id: CID,
                    max_age_secs: 0,
                    cursor: None,
                    fingerprint: Vec::new(),
                    epoch_root_known: None,
                    round: 0,
                    meta_cursor: None,
                    revision: 0,
                },
            );
            outstanding.insert(id);
            straggler_id = Some(id);
        }
        svc.reconcile_triggered.insert(CID);
        svc.pending_reconcile_comparisons.insert(
            CID,
            ReconcileComparison {
                outstanding,
                candidates,
                deadline: Instant::now(),
                any_capped,
            },
        );
        straggler_id
    }

    fn recheck_minutes(svc: &NetworkService) -> Option<u64> {
        svc.reconcile_throttle
            .entry(&CID)
            .map(|e| e.next_due.saturating_duration_since(Instant::now()).as_secs() / 60)
    }

    #[tokio::test]
    async fn all_in_sync_candidates_move_the_throttle_to_the_recheck_and_never_complete() {
        let (mut svc, _d) = service().await;
        let pages = fixture(&svc, 3, &[3, 3], 1_000);
        svc.reconcile_throttle.on_dispatch(CID, Instant::now(), 0.0);
        let (a, b) = (PeerId::random(), PeerId::random());
        open_comparison(&mut svc, vec![(a, pages[0].clone()), (b, pages[1].clone())], false, false);
        svc.finalize_reconcile_comparison(CID);
        let m = recheck_minutes(&svc).expect("throttle entry");
        assert!((47..=72).contains(&m), "in-sync recheck ≈ 60 min ± 20 %: {m}");
        assert_eq!(svc.reconcile_throttle.entry(&CID).unwrap().failures, 0);
        assert_eq!(svc.storage.channel_backfill_completed_at(CID), None, "IN_SYNC is never COMPLETE");
        assert!(!svc.reconcile_triggered.contains(&CID), "dedup guard released");
        assert_eq!(svc.counters.reconcile_in_sync_outcomes.load(Ordering::Relaxed), 1);
        assert!(svc.peer_reconcile_health.is_empty(), "no winner: peer health untouched");
    }

    #[tokio::test]
    async fn in_sync_negative_controls_keep_the_dispatch_backoff() {
        // Each case: the dispatch stamp (30 s) must survive.
        for case in ["straggler", "capped", "stale", "multi_page", "forged", "rejected"] {
            let (mut svc, _d) = service().await;
            let cap = if case == "multi_page" { 2 } else { 1_000 };
            let mut pages = fixture(&svc, 3, &[3], cap);
            let peer = PeerId::random();
            match case {
                "stale" => {
                    svc.peer_reconcile_health.insert(
                        peer,
                        PeerReconcileHealth {
                            consecutive_losses: svc.backfill_config.stale_peer_threshold,
                            last_probed_at: None,
                            last_touched: Instant::now(),
                        },
                    );
                }
                "forged" => {
                    let mut e: Envelope = rmp_serde::from_slice(&pages[0].envelopes[0]).unwrap();
                    e.signature = vec![0xAB; 64];
                    pages[0].envelopes[0] = rmp_serde::to_vec_named(&e).unwrap();
                }
                "rejected" => pages[0].envelopes.push(vec![0xFF, 0x00]),
                _ => {}
            }
            svc.reconcile_throttle.on_dispatch(CID, Instant::now(), 0.0);
            open_comparison(&mut svc, vec![(peer, pages[0].clone())], case == "straggler", case == "capped");
            svc.finalize_reconcile_comparison(CID);
            let m = recheck_minutes(&svc).expect("throttle entry kept");
            assert!(m < 1, "{case}: kept the 30 s dispatch backoff, got {m} min");
            assert_eq!(svc.storage.channel_backfill_completed_at(CID), None, "{case}");
            assert_eq!(svc.counters.reconcile_in_sync_outcomes.load(Ordering::Relaxed), 0, "{case}");
        }
    }

    #[tokio::test]
    async fn ghost_with_a_verified_subset_cannot_hide_the_honest_peers_new_message() {
        for ghost_first in [false, true] {
            let (mut svc, _d) = service().await;
            let mut pages = fixture(&svc, 3, &[3, 4], 1_000);
            if ghost_first {
                // Pad the ghost's page with repeats so it ranks first.
                let extra = pages[0].envelopes.clone();
                pages[0].envelopes.extend(extra.iter().cloned());
                pages[0].envelopes.extend(extra);
            }
            svc.reconcile_throttle.on_dispatch(CID, Instant::now(), 0.0);
            let (ghost, honest) = (PeerId::random(), PeerId::random());
            open_comparison(&mut svc, vec![(ghost, pages[0].clone()), (honest, pages[1].clone())], false, false);
            svc.finalize_reconcile_comparison(CID);
            assert!(svc.storage.channel_backfill_completed_at(CID).is_some(), "honest peer won → COMPLETE");
            assert!(svc.reconcile_throttle.entry(&CID).is_none(), "COMPLETE clears the throttle");
            assert_eq!(svc.counters.reconcile_in_sync_outcomes.load(Ordering::Relaxed), 0);
            let ghost_losses = svc.peer_reconcile_health.get(&ghost).map(|h| h.consecutive_losses);
            assert_eq!(ghost_losses, if ghost_first { Some(1) } else { None }, "ghost_first={ghost_first}");
        }
    }

    #[tokio::test]
    async fn no_stamp_on_early_returns_and_the_gate_holds() {
        let (mut svc, _d) = service().await;
        let c = wallet();
        setup_public_channel(&svc.storage, &c.addr);
        // No connected peers → no candidates → no stamp.
        svc.maybe_trigger_backfill(CID);
        assert!(svc.reconcile_throttle.entry(&CID).is_none(), "no stamp without candidates");
        assert!(!svc.reconcile_triggered.contains(&CID));
        assert_eq!(svc.counters.reconcile_attempts_dispatched.load(Ordering::Relaxed), 0);
        // A not-ready entry is left untouched by the gate.
        svc.reconcile_throttle.on_dispatch(CID, Instant::now(), 0.0);
        svc.maybe_trigger_backfill(CID);
        assert_eq!(svc.reconcile_throttle.entry(&CID).unwrap().failures, 1);
        assert!(!svc.reconcile_triggered.contains(&CID));

        // Private channel: no claim, and (with a fresh claim) no candidates.
        let pcid = (1u64 << 40) + 9;
        svc.storage
            .put_cf(schema::cf::CHANNELS, &pcid.to_be_bytes(), br#"{"channel_type":2,"history_visibility":1}"#)
            .unwrap();
        let w = wallet();
        svc.storage.add_channel_member(pcid, &w.addr, 1, "member").unwrap();
        svc.maybe_trigger_private_channel_sync(pcid, &w.addr, None, false);
        let key = (w.addr.clone(), pcid);
        assert!(svc.private_channel_sync_throttle.entry(&key).is_none(), "no stamp without a claim");
        let claim = private_channel_sync::WalletAuthClaim { timestamp: now_ms(), signature: vec![0; 64], device: None };
        svc.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim), true);
        assert!(svc.private_channel_sync_throttle.entry(&key).is_none(), "no stamp without candidates");
        assert!(!svc.private_channel_sync_triggered.contains(&key));
        assert_eq!(svc.counters.private_sync_attempts_dispatched.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_server_capped_answer_recorded_into_the_comparison_blocks_in_sync() {
        for capped in [false, true] {
            let (mut svc, _d) = service().await;
            let pages = fixture(&svc, 3, &[3], 1_000);
            svc.reconcile_throttle.on_dispatch(CID, Instant::now(), 0.0);
            let id = open_comparison(&mut svc, vec![(PeerId::random(), pages[0].clone())], true, false)
                .expect("straggler id");
            // The last outstanding candidate answers: capped, or (control)
            // uninformative-empty. Either way it finalizes the comparison.
            let mut answer = reconcile::capped_response(&reconcile::ReconcileRequest {
                channel_id: CID,
                max_age_secs: 0,
                cursor: None,
                fingerprint: Vec::new(),
                epoch_root_known: None,
                round: 0,
                meta_cursor: None,
                revision: 0,
            });
            answer.server_capped = capped;
            svc.record_reconcile_comparison_response(CID, id, PeerId::random(), answer);
            assert!(!svc.pending_reconcile_comparisons.contains_key(&CID), "finalized");
            let in_sync = svc.counters.reconcile_in_sync_outcomes.load(Ordering::Relaxed);
            assert_eq!(in_sync, if capped { 0 } else { 1 }, "capped={capped}");
        }
    }

    /// Two unrelated services connected over loopback TCP, so the trigger
    /// has a real candidate peer. Only the swarms are polled (no event
    /// handling) — the connection itself is all the trigger needs.
    async fn connected_pair() -> (NetworkService, TempDir, NetworkService, TempDir) {
        let (mut a, da) = service().await;
        let (mut b, db) = service().await;
        let b_id = *b.swarm.local_peer_id();
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = b.swarm.select_next_some().await {
                let s = address.to_string();
                if s.starts_with("/ip4/127.0.0.1/tcp/") {
                    break address;
                }
            }
        };
        a.swarm.dial(addr).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while !a.swarm.is_connected(&b_id) {
            assert!(tokio::time::Instant::now() < deadline, "loopback connection timed out");
            tokio::select! {
                _ = a.swarm.select_next_some() => {}
                _ = b.swarm.select_next_some() => {}
            }
        }
        (a, da, b, db)
    }

    /// [`connected_pair`] where `b` subscribes `cid`'s gossip topic and
    /// `a` has seen that subscription — `b` is a known host of the channel,
    /// which a non-federated private-sync pair needs (l2-node 0.150.0
    /// no-host gate).
    async fn connected_pair_subscribed(cid: u64) -> (NetworkService, TempDir, NetworkService, TempDir) {
        let (mut a, da, mut b, db) = connected_pair().await;
        subscribe_remote(&mut a, &mut b, cid).await;
        (a, da, b, db)
    }

    /// `b` subscribes `cid`'s topic; pump both swarms until `a` knows it.
    async fn subscribe_remote(a: &mut NetworkService, b: &mut NetworkService, cid: u64) {
        let topic = libp2p::gossipsub::IdentTopic::new(gossip::channel_topic(b.topics.network_id(), cid));
        b.swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
        let hash = topic.hash();
        let b_id = *b.swarm.local_peer_id();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while !a
            .swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .any(|(p, t)| *p == b_id && t.iter().any(|h| **h == hash))
        {
            assert!(tokio::time::Instant::now() < deadline, "subscription announcement timed out");
            tokio::select! {
                _ = a.swarm.select_next_some() => {}
                _ = b.swarm.select_next_some() => {}
            }
        }
    }

    #[tokio::test]
    async fn the_throttle_gate_holds_back_a_dispatch_to_a_real_candidate() {
        let (mut a, _da, _b, _db) = connected_pair().await;
        let c = wallet();
        setup_public_channel(&a.storage, &c.addr);
        // Gate closed: a not-ready entry → nothing is sent, entry untouched.
        a.reconcile_throttle.on_dispatch(CID, Instant::now(), 0.0);
        a.maybe_trigger_backfill(CID);
        assert!(a.pending_reconcile_requests.is_empty(), "throttle gate must hold back the dispatch");
        assert!(a.pending_reconcile_comparisons.is_empty());
        assert_eq!(a.reconcile_throttle.entry(&CID).unwrap().failures, 1);
        assert!(!a.reconcile_triggered.contains(&CID));
        // Positive control: gate open (entry cleared) → dispatched + stamped.
        a.reconcile_throttle.on_complete(&CID);
        a.maybe_trigger_backfill(CID);
        assert_eq!(a.pending_reconcile_requests.len(), 1, "dispatched to the connected peer");
        assert_eq!(a.reconcile_throttle.entry(&CID).unwrap().failures, 1, "stamped at dispatch");
        assert_eq!(a.counters.reconcile_attempts_dispatched.load(Ordering::Relaxed), 1);
        // A second trigger right after is held back by the fresh stamp.
        a.reconcile_triggered.clear();
        a.pending_reconcile_requests.clear();
        a.pending_reconcile_comparisons.clear();
        a.maybe_trigger_backfill(CID);
        assert!(a.pending_reconcile_requests.is_empty(), "fresh dispatch backoff holds");
    }

    #[tokio::test]
    async fn the_private_gate_and_federate_floor_hold_back_redispatch() {
        let pcid = (1u64 << 40) + 9;
        let (mut a, _da, _b, _db) = connected_pair_subscribed(pcid).await;
        a.storage
            .put_cf(schema::cf::CHANNELS, &pcid.to_be_bytes(), br#"{"channel_type":2,"history_visibility":1}"#)
            .unwrap();
        let w = wallet();
        a.storage.add_channel_member(pcid, &w.addr, 1, "member").unwrap();
        let key = (w.addr.clone(), pcid);
        let claim = || private_channel_sync::WalletAuthClaim { timestamp: now_ms(), signature: vec![0; 64], device: None };
        let sent = |a: &NetworkService| a.pending_private_channel_sync_requests.len();
        // First federate call: dispatched and stamped.
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim()), true);
        assert_eq!(sent(&a), 1);
        assert_eq!(a.private_channel_sync_throttle.entry(&key).unwrap().failures, 1);
        a.pending_private_channel_sync_requests.clear();
        a.private_channel_sync_triggered.clear();
        // A sweep (cached claim, no bypass) is held back by the gate…
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, None, false);
        assert_eq!(sent(&a), 0, "throttle gate holds the sweep");
        // …and so is a fresh federate call inside the 60 s floor.
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim()), true);
        assert_eq!(sent(&a), 0, "federate bypass refused inside the floor");
        assert_eq!(a.private_channel_sync_throttle.entry(&key).unwrap().failures, 1);
        // Positive control: once the stamp is 60 s old, a fresh federate
        // call bypasses the (still not-ready) gate.
        let mut e = a.private_channel_sync_throttle.entry(&key).unwrap();
        e.last_dispatch = e.last_dispatch.and_then(|t| t.checked_sub(Duration::from_secs(61)));
        a.private_channel_sync_throttle.set_entry_for_test(key.clone(), e);
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, None, false);
        assert_eq!(sent(&a), 0, "sweep still held: the bypass needs a fresh claim");
        // l2-node 0.142.0: an auth-path claim refresh never bypasses, even
        // with a fresh claim and the floor passed.
        a.storage
            .put_cf(
                schema::cf::LOCAL_CHANNEL_FED,
                &schema::encode_local_channel_fed_key(&w.addr, pcid),
                &now_ms().to_be_bytes(),
            )
            .unwrap();
        a.refresh_private_channel_sync_claim(&w.addr, Some(claim()));
        assert_eq!(sent(&a), 0, "claim refresh is throttled, never a bypass");
        assert!(a.private_channel_sync_wallet_claims.contains_key(&w.addr), "claim cached");
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim()), true);
        assert_eq!(sent(&a), 1, "fresh federate claim past the floor bypasses");
        assert_eq!(a.private_channel_sync_throttle.entry(&key).unwrap().failures, 2);
    }

    #[tokio::test]
    async fn revoked_or_expired_claims_are_not_usable() {
        let (svc, _d) = service().await;
        let dev_sk = ed25519_dalek::SigningKey::from_bytes(&[77u8; 32]);
        let dev_addr = crate::crypto::device_pubkey_to_address(&dev_sk.verifying_key()).unwrap();
        let now = now_ms();
        let device_claim = private_channel_sync::WalletAuthClaim {
            timestamp: now,
            signature: vec![0; 64],
            device: Some(private_channel_sync::DeviceAuthProof {
                device_pubkey: dev_sk.verifying_key().to_bytes().to_vec(),
                delegation_timestamp: now - 10_000,
                delegation_signature: vec![0; 64],
            }),
        };
        let direct = private_channel_sync::WalletAuthClaim { device: None, ..device_claim.clone() };
        assert!(svc.private_channel_sync_claim_usable("klv1test", &device_claim));
        svc.storage
            .put_cf(schema::cf::DEVICE_REVOCATIONS, dev_addr.as_bytes(), &(now - 5_000).to_be_bytes())
            .unwrap();
        assert!(!svc.private_channel_sync_claim_usable("klv1test", &device_claim), "device revoked after its delegation");
        assert!(svc.private_channel_sync_claim_usable("klv1test", &direct));
        let stale = private_channel_sync::WalletAuthClaim { timestamp: now - 400_000, ..direct };
        assert!(!svc.private_channel_sync_claim_usable("klv1test", &stale), "expired");
    }

    #[tokio::test]
    async fn claim_refresh_dispatches_when_the_gate_is_open_and_keeps_the_freshest() {
        let (mut a, _da, _b, _db) = connected_pair().await;
        let pcid = (1u64 << 40) + 11;
        a.storage
            .put_cf(schema::cf::CHANNELS, &pcid.to_be_bytes(), br#"{"channel_type":2,"history_visibility":1}"#)
            .unwrap();
        let w = wallet();
        a.storage.add_channel_member(pcid, &w.addr, 1, "member").unwrap();
        a.storage
            .put_cf(
                schema::cf::LOCAL_CHANNEL_FED,
                &schema::encode_local_channel_fed_key(&w.addr, pcid),
                &now_ms().to_be_bytes(),
            )
            .unwrap();
        let at = |ts| private_channel_sync::WalletAuthClaim { timestamp: ts, signature: vec![0; 64], device: None };
        let now = now_ms();
        a.refresh_private_channel_sync_claim(&w.addr, Some(at(now)));
        assert_eq!(a.pending_private_channel_sync_requests.len(), 1, "open gate: dispatched");
        // An OLDER claim never replaces the cached fresher one.
        a.refresh_private_channel_sync_claim(&w.addr, Some(at(now - 10_000)));
        assert_eq!(a.private_channel_sync_wallet_claims[&w.addr].timestamp, now);
        // No claim → nothing happens.
        a.pending_private_channel_sync_requests.clear();
        a.private_channel_sync_triggered.clear();
        a.refresh_private_channel_sync_claim(&w.addr, None);
        assert_eq!(a.pending_private_channel_sync_requests.len(), 0);
    }

    #[tokio::test]
    async fn only_a_comparison_first_page_can_be_in_sync_evidence() {
        let (mut svc, _d) = service().await;
        let pages = fixture(&svc, 3, &[3], 1_000);
        let peer = PeerId::random();
        let pending = |pages_fetched| ReconcilePending {
            peer_id: peer,
            channel_id: CID,
            pages_fetched,
            consecutive_unproductive_pages: 0,
            total_accepted: 0,
            meta: ReconcileMetaState::default(),
        };
        // Positive control: a comparison trial's first page.
        let out = svc.apply_reconcile_response(pending(0), peer, pages[0].clone(), false);
        assert!(matches!(out, ReconcileApplyOutcome::NoProgress { verified_in_sync: true, .. }));
        // The same page on the direct (continuation) path is not evidence.
        svc.reconcile_triggered.insert(CID);
        let out = svc.apply_reconcile_response(pending(3), peer, pages[0].clone(), true);
        assert!(matches!(out, ReconcileApplyOutcome::NoProgress { verified_in_sync: false, meta_followup: false }));
    }

    #[tokio::test]
    async fn accepted_but_incomplete_session_resets_the_backoff() {
        let (mut svc, _d) = service().await;
        let pages = fixture(&svc, 0, &[3], 2); // 2 new messages, has_more
        assert!(pages[0].has_more);
        for _ in 0..3 {
            svc.reconcile_throttle.on_dispatch(CID, Instant::now(), 0.0);
        }
        assert_eq!(svc.reconcile_throttle.entry(&CID).unwrap().failures, 3);
        let peer = PeerId::random();
        svc.reconcile_triggered.insert(CID);
        // The page that hits the page-count backstop admits new content.
        let pending = ReconcilePending {
            peer_id: peer,
            channel_id: CID,
            pages_fetched: MAX_PAGES_PER_SESSION - 1,
            consecutive_unproductive_pages: 0,
            total_accepted: 0,
            meta: ReconcileMetaState::default(),
        };
        let out = svc.apply_reconcile_response(pending, peer, pages[0].clone(), true);
        assert!(matches!(out, ReconcileApplyOutcome::NoProgress { verified_in_sync: false, meta_followup: false }));
        let e = svc.reconcile_throttle.entry(&CID).unwrap();
        assert_eq!(e.failures, 0, "backoff reset");
        assert!(e.next_due.saturating_duration_since(Instant::now()) <= budget::BASE_RETRY);
        assert_eq!(svc.storage.channel_backfill_completed_at(CID), None);
        // Negative control: the same backstop with NOTHING accepted keeps
        // the dispatch backoff.
        let (mut svc, _d) = service().await;
        let pages = fixture(&svc, 3, &[3], 2); // all duplicates, has_more
        for _ in 0..3 {
            svc.reconcile_throttle.on_dispatch(CID, Instant::now(), 0.0);
        }
        svc.reconcile_triggered.insert(CID);
        let pending = ReconcilePending {
            peer_id: peer,
            channel_id: CID,
            pages_fetched: MAX_PAGES_PER_SESSION - 1,
            consecutive_unproductive_pages: 0,
            total_accepted: 0,
            meta: ReconcileMetaState::default(),
        };
        svc.apply_reconcile_response(pending, peer, pages[0].clone(), true);
        assert_eq!(svc.reconcile_throttle.entry(&CID).unwrap().failures, 3);
    }

    #[test]
    fn comparison_in_sync_conditions() {
        let (a, b) = (PeerId::random(), PeerId::random());
        let never_stale = |_: &PeerId| false;
        assert!(comparison_in_sync(true, false, &[(a, true), (b, true)], never_stale));
        // Negative controls, one condition each.
        assert!(!comparison_in_sync(false, false, &[(a, true)], never_stale), "straggler");
        assert!(!comparison_in_sync(true, true, &[(a, true)], never_stale), "a capped candidate");
        assert!(!comparison_in_sync(true, false, &[], never_stale), "nobody tried");
        assert!(!comparison_in_sync(true, false, &[(a, true), (b, false)], never_stale), "one trial unverified");
        assert!(!comparison_in_sync(true, false, &[(a, true)], |p| *p == a), "sole in-sync peer is stale");
        assert!(comparison_in_sync(true, false, &[(a, true), (b, true)], |p| *p == a), "one healthy in-sync peer");
    }

    #[test]
    fn verified_in_sync_page_conditions() {
        let clean = ReconcileTally { admitted: 3, verified_dups: 3, ..Default::default() };
        assert!(clean.is_verified_in_sync_page(3, false));
        assert!(!clean.is_verified_in_sync_page(3, true), "has_more");
        assert!(!clean.is_verified_in_sync_page(4, false), "an envelope not verified");
        assert!(!ReconcileTally::default().is_verified_in_sync_page(0, false), "empty page");
        assert!(!ReconcileTally { tainted: true, ..clean }.is_verified_in_sync_page(3, false), "tainted");
        assert!(!ReconcileTally { newly_accepted: 1, ..clean }.is_verified_in_sync_page(3, false), "new content");
    }

    #[test]
    fn duplicate_is_verified_compares_stored_bytes() {
        let (r, s, _d) = responder();
        let c = wallet();
        setup_public_channel(&s, &c.addr);
        let m = chat(&c, T0);
        feed(&r, &m);
        assert!(duplicate_is_verified(&s, &m), "identical bytes");
        // Same msg_id, different bytes (forged signature) → false.
        let mut e: Envelope = rmp_serde::from_slice(&m).unwrap();
        e.signature = vec![0xAB; 64];
        let forged = rmp_serde::to_vec_named(&e).unwrap();
        assert!(matches!(r.process_synced_message(&forged), RouteResult::Duplicate), "router says Duplicate");
        assert!(!duplicate_is_verified(&s, &forged), "forged duplicate");
        // Missing and undecodable.
        assert!(!duplicate_is_verified(&s, &chat(&c, T0 + 1)), "not stored");
        assert!(!duplicate_is_verified(&s, &[0xFF, 0x00, 0x01]), "undecodable");
    }

    // --- private-channel lifecycle (l2-node 0.149.0) -------------------

    impl NetworkService {
        /// `lifecycle_backstop` with the page reads run inline, until one
        /// full rotation of the scan completed (tests).
        fn lifecycle_backstop_sync(&mut self) {
            self.lifecycle_backstop_tick();
            loop {
                let result = self
                    .storage
                    .private_channel_lifecycle_page(&self.lifecycle_scan_cursor, LIFECYCLE_BACKSTOP_PAGE)
                    .map_err(|e| e.to_string());
                self.lifecycle_scan_in_flight = true;
                self.apply_lifecycle_scan_page(LifecycleScanPage { result });
                if self.lifecycle_scan_cursor.is_empty() {
                    return;
                }
            }
        }
    }

    fn put_private_channel(s: &Storage, cid: u64) {
        s.put_cf(schema::cf::CHANNELS, &cid.to_be_bytes(), br#"{"channel_type":2,"history_visibility":1}"#)
            .unwrap();
    }

    fn put_lifecycle_row(s: &Storage, cid: u64) {
        let row = br#"{"v":1,"state":"pending","since_ms":1,"deadline_ms":2,"reason":"no_local_member"}"#;
        s.put_cf(schema::cf::PRIVATE_CHANNEL_LIFECYCLE, &cid.to_be_bytes(), row).unwrap();
    }

    #[tokio::test]
    async fn startup_skips_private_channels_pending_cleanup_but_not_pinned_or_public() {
        let (mut a, _d) = service().await;
        let pending = (1u64 << 40) + 1;
        let live = (1u64 << 40) + 2;
        let pinned = (1u64 << 40) + 3;
        assert!(a.storage.set_private_channel_policy(
            crate::storage::channel_lifecycle::PrivateChannelPolicy::new(168, [pinned]),
        ));
        for cid in [pending, live, pinned] {
            put_private_channel(&a.storage, cid);
        }
        a.storage.put_cf(schema::cf::CHANNELS, &CID.to_be_bytes(), br#"{"channel_type":0}"#).unwrap();
        put_lifecycle_row(&a.storage, pending);
        put_lifecycle_row(&a.storage, pinned);
        // Even a (forged) row for a public id never blocks it.
        put_lifecycle_row(&a.storage, CID);
        let n = a.subscribe_stored_channels(&[pinned]);
        assert_eq!(n, 3);
        assert!(!a.topics.is_channel_subscribed(pending));
        assert!(a.lifecycle_unsubscribed.contains(&pending));
        for cid in [live, pinned, CID] {
            assert!(a.topics.is_channel_subscribed(cid), "{cid} must be subscribed");
            assert!(!a.lifecycle_unsubscribed.contains(&cid));
        }
    }

    #[tokio::test]
    async fn channel_rx_subscribe_respects_the_lifecycle_and_resubscribes_after_cancel() {
        let (mut a, _d) = service().await;
        let cid = (1u64 << 40) + 4;
        put_private_channel(&a.storage, cid);
        put_lifecycle_row(&a.storage, cid);
        // Chain discovery / federate / create re-subscribe request: refused.
        a.handle_channel_subscribe_request(cid);
        assert!(!a.topics.is_channel_subscribed(cid));
        assert!(a.lifecycle_unsubscribed.contains(&cid));
        // Row cancelled (member returned) → the notifier-driven reconcile
        // subscribes again and counts it.
        a.storage.delete_cf(schema::cf::PRIVATE_CHANNEL_LIFECYCLE, &cid.to_be_bytes()).unwrap();
        a.reconcile_channel_lifecycle(cid);
        assert!(a.topics.is_channel_subscribed(cid));
        assert!(!a.lifecycle_unsubscribed.contains(&cid));
        assert_eq!(a.counters.private_channel_resubscribes.load(Ordering::Relaxed), 1);
        // A plain subscribe request with no row behaves as before.
        let other = (1u64 << 40) + 5;
        put_private_channel(&a.storage, other);
        a.handle_channel_subscribe_request(other);
        assert!(a.topics.is_channel_subscribed(other));
    }

    #[tokio::test]
    async fn reconcile_unsubscribes_but_never_public_or_pinned_and_backstop_converges() {
        let (mut a, _d) = service().await;
        let cid = (1u64 << 40) + 6;
        let pinned = (1u64 << 40) + 7;
        a.storage.set_private_channel_policy(
            crate::storage::channel_lifecycle::PrivateChannelPolicy::new(168, [pinned]),
        );
        for c in [cid, pinned] {
            put_private_channel(&a.storage, c);
            a.subscribe_channel(c);
            put_lifecycle_row(&a.storage, c);
        }
        a.subscribe_channel(CID);
        put_lifecycle_row(&a.storage, CID);
        a.lifecycle_backstop_sync();
        assert!(!a.topics.is_channel_subscribed(cid), "no local member → unsubscribed");
        assert!(a.topics.is_channel_subscribed(pinned), "pinned always subscribed");
        assert!(a.topics.is_channel_subscribed(CID), "public id never touched");
        assert_eq!(a.counters.private_channel_unsubscribes.load(Ordering::Relaxed), 1);
        assert_eq!(a.counters.private_channels_pending.load(Ordering::Relaxed), 3);
        // Idempotent.
        a.lifecycle_backstop_sync();
        assert_eq!(a.counters.private_channel_unsubscribes.load(Ordering::Relaxed), 1);
        // The row disappears without a notification: the backstop re-subscribes.
        a.storage.delete_cf(schema::cf::PRIVATE_CHANNEL_LIFECYCLE, &cid.to_be_bytes()).unwrap();
        a.lifecycle_backstop_sync();
        assert!(a.topics.is_channel_subscribed(cid));
        assert_eq!(a.counters.private_channel_resubscribes.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_finished_purge_does_not_resubscribe_the_topic() {
        let (mut a, _d) = service().await;
        let cid = (1u64 << 40) + 10;
        put_private_channel(&a.storage, cid);
        a.subscribe_channel(cid);
        put_lifecycle_row(&a.storage, cid);
        a.reconcile_channel_lifecycle(cid);
        assert!(!a.topics.is_channel_subscribed(cid));
        // The purge reaper deleted the channel row, its data and finally the
        // lifecycle row: the channel no longer exists here.
        a.storage.delete_cf(schema::cf::CHANNELS, &cid.to_be_bytes()).unwrap();
        a.storage.delete_cf(schema::cf::PRIVATE_CHANNEL_LIFECYCLE, &cid.to_be_bytes()).unwrap();
        a.lifecycle_backstop_sync();
        assert!(!a.topics.is_channel_subscribed(cid), "a purged channel stays unsubscribed");
        assert!(!a.lifecycle_unsubscribed.contains(&cid));
        assert_eq!(a.counters.private_channel_resubscribes.load(Ordering::Relaxed), 0);
        // A later re-federation subscribes through `channel_rx` as usual.
        put_private_channel(&a.storage, cid);
        a.handle_channel_subscribe_request(cid);
        assert!(a.topics.is_channel_subscribed(cid));
    }

    #[tokio::test]
    async fn the_storage_notifier_reaches_the_service() {
        let (mut a, _d) = service().await;
        let mut rx = a.lifecycle_rx.take().expect("the first service owns the notifier");
        let cid = (1u64 << 40) + 8;
        put_private_channel(&a.storage, cid);
        // Local data → a cleanup row is written (a bare id would get none).
        a.storage
            .put_cf(schema::cf::CHANNEL_MSGS, &schema::encode_channel_msg_key(cid, 5, &[7; 32]), &[])
            .unwrap();
        a.storage.tombstone_channel(cid, 1, None).unwrap();
        assert_eq!(rx.try_recv().ok(), Some(cid), "a deleted private channel notifies");
    }

    /// Audit W4: the backstop tick never scans the lifecycle CF on the
    /// event loop — a row nobody was notified about is converged by the
    /// off-loop page read, whose result comes back over a channel.
    #[tokio::test]
    async fn the_backstop_reads_the_lifecycle_cf_off_the_event_loop() {
        let (mut a, _d) = service().await;
        let mut rx = a.lifecycle_scan_rx.take().expect("scan receiver");
        let cid = (1u64 << 40) + 11;
        put_private_channel(&a.storage, cid);
        a.subscribe_channel(cid);
        put_lifecycle_row(&a.storage, cid); // no notification
        a.lifecycle_backstop();
        assert!(a.topics.is_channel_subscribed(cid), "the tick itself did not scan");
        assert!(a.lifecycle_scan_in_flight);
        a.lifecycle_backstop(); // a second tick while the read runs: no second read
        let page = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(200), rx.recv()).await.is_err(), "one read at a time");
        a.apply_lifecycle_scan_page(page);
        assert!(!a.topics.is_channel_subscribed(cid), "converged from the page");
        assert!(a.lifecycle_unsubscribed.contains(&cid));
        assert_eq!(a.counters.private_channels_pending.load(Ordering::Relaxed), 1, "rotation done → gauge");
        assert!(!a.lifecycle_scan_in_flight);
    }

    /// Round-2 note: a page read that panics (or never runs) still reports
    /// back, so the in-flight flag is cleared and the scan continues.
    #[tokio::test]
    async fn a_failed_backstop_page_read_clears_the_in_flight_flag() {
        let (mut a, _d) = service().await;
        let mut rx = a.lifecycle_scan_rx.take().expect("scan receiver");
        let guard = LifecycleScanSendGuard(Some(a.lifecycle_scan_tx.clone()));
        let joined = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            panic!("simulated page-read panic");
        })
        .await;
        assert!(joined.is_err(), "the task panicked");
        let page = rx.try_recv().expect("an error page was delivered");
        assert!(page.result.is_err());
        a.lifecycle_scan_in_flight = true;
        a.apply_lifecycle_scan_page(page);
        assert!(!a.lifecycle_scan_in_flight);
        // A normal send delivers exactly one page (no extra from Drop).
        let mut g = LifecycleScanSendGuard(Some(a.lifecycle_scan_tx.clone()));
        g.send(LifecycleScanPage { result: Ok((Vec::new(), None)) });
        drop(g);
        assert!(rx.try_recv().unwrap().result.is_ok());
        assert!(rx.try_recv().is_err());
    }

    /// Security round 2 B1: a healing walk (the wallet lost its membership
    /// here, standing only through its home row) always starts FRESH from
    /// the first page — a high-water catch-up could skip the re-join that
    /// an old replayed kick removed.
    #[tokio::test]
    async fn a_healing_walk_ignores_the_high_water_mark() {
        let pcid = (1u64 << 40) + 36;
        let (mut a, _da, _b, _db) = connected_pair_subscribed(pcid).await;
        put_private_channel(&a.storage, pcid);
        let w = wallet();
        a.storage.add_channel_member(pcid, &w.addr, 1, "member").unwrap();
        a.storage.put_local_channel_home_for_test(pcid, &w.addr, 0, 0).unwrap();
        let mark = private_channel_sync::ResumeRow {
            v: private_channel_sync::RESUME_ROW_VERSION,
            phase: None,
            meta_cursor: None,
            chat_cursor: None,
            meta_done: false,
            accepted_total: 0,
            sessions: 1,
            peer: PeerId::random().to_string(),
            updated_at: now_ms(),
            hw: Some(private_channel_sync::ResumeHighWater {
                meta: Some(reconcile::MetaCursor { tier: 1, ts: now_ms() - 1_000, msg_id: [1; 32] }),
                chat: None,
            }),
            walk_hw: None,
            stalls: 0,
            fresh_walk_at: now_ms() - 1_000,
            same_peer_sessions: 0,
        };
        a.storage.put_private_channel_sync_resume(&w.addr, pcid, &serde_json::to_vec(&mark).unwrap()).unwrap();
        let key = (w.addr.clone(), pcid);
        let claim = private_channel_sync::WalletAuthClaim { timestamp: now_ms(), signature: vec![0; 64], device: None };
        // Control: a member catches up from the mark.
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim.clone()), true);
        let p = a.pending_private_channel_sync_requests.values().next().unwrap();
        assert!(p.session.last_meta_cursor.is_some(), "member: catch-up");
        a.pending_private_channel_sync_requests.clear();
        a.private_channel_sync_throttle.on_complete(&key);
        a.private_channel_sync_triggered.clear();
        // The old kick lands: the healing walk requests metadata from the start.
        a.storage.remove_channel_member_and_raise_epoch_floor(pcid, &w.addr).unwrap();
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim), true);
        let p = a.pending_private_channel_sync_requests.values().next().unwrap();
        assert_eq!(p.session, private_channel_sync::SyncSession::default(), "fresh walk from page 1");
        assert_eq!(p.session.request_cursors(), (None, None, false));
        assert!(p.resume.as_ref().is_some_and(|s| s.sessions == 1 && s.fresh_walk_at > 0));
    }

    /// Round 4 W3: a ForwardOnly member's fanout start is floored at its own
    /// earliest recorded join minus the overlap; without a recorded join
    /// (or for FullHistory) there is no floor.
    #[tokio::test]
    async fn a_forward_only_member_starts_chat_at_its_join_floor() {
        let pcid = (1u64 << 40) + 37;
        let (mut a, _da, _b, _db) = connected_pair_subscribed(pcid).await;
        a.storage
            .put_cf(schema::cf::CHANNELS, &pcid.to_be_bytes(), br#"{"channel_type":2,"history_visibility":0,"creator":"klv1c"}"#)
            .unwrap();
        let w = wallet();
        let joined = now_ms() - 10 * 24 * 3_600_000;
        a.storage.add_channel_member(pcid, &w.addr, joined + 5_000, "member").unwrap();
        let key = (w.addr.clone(), pcid);
        let claim = private_channel_sync::WalletAuthClaim { timestamp: now_ms(), signature: vec![0; 64], device: None };
        // No recorded join: no floor.
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim.clone()), true);
        assert_eq!(a.pending_private_channel_sync_requests.values().next().unwrap().session.last_chat_cursor, None);
        a.pending_private_channel_sync_requests.clear();
        a.private_channel_sync_throttle.on_complete(&key);
        a.private_channel_sync_triggered.clear();
        // The signed join recorded in the membership index: floored.
        a.storage
            .index_membership_event(pcid, &w.addr, crate::storage::rocks::MembershipEvent::Join, joined, &[3; 32])
            .unwrap();
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim), true);
        let p = a.pending_private_channel_sync_requests.values().next().unwrap();
        let overlap = a.private_channel_sync_config.catchup_overlap_hours * 3_600_000;
        assert_eq!(p.session.last_chat_cursor.as_ref().map(|c| c.after_lamport_ts), Some(joined - overlap));
        assert_eq!(p.session.verified_chat_hw, None);
    }

    /// Security round 2 W-C: the backstop tick re-reads the unsubscribed set
    /// in rotating batches of at most one page, not all of it per tick.
    #[tokio::test]
    async fn the_backstop_tick_rotates_over_a_large_unsubscribed_set() {
        let (mut a, _d) = service().await;
        let base = (1u64 << 40) + 10_000;
        // Rows gone, channels gone: each reconcile drops the id from the set.
        for i in 0..1_500u64 {
            a.lifecycle_unsubscribed.insert(base + i);
        }
        a.lifecycle_backstop_tick();
        assert_eq!(a.lifecycle_unsubscribed.len(), 1_500 - LIFECYCLE_BACKSTOP_PAGE, "one batch per tick");
        assert!(a.lifecycle_unsubscribed.iter().all(|&c| c >= base + LIFECYCLE_BACKSTOP_PAGE as u64), "lowest ids first");
        a.lifecycle_backstop_tick();
        assert!(a.lifecycle_unsubscribed.is_empty(), "the rotation reached the rest");
        assert_eq!(a.lifecycle_unsub_cursor, 0, "wrapped");
    }

    /// Audit W2: an OLD kick replayed after a federation removed a local
    /// home's membership while its newer re-join is still withheld — the
    /// healing walk must still be dispatched, and its progress persisted.
    #[tokio::test]
    async fn the_healing_sync_is_dispatched_for_a_local_home_that_lost_membership() {
        use libp2p::request_response::{Event, Message};
        let pcid = (1u64 << 40) + 35;
        let (mut a, _da, b, _db) = connected_pair_subscribed(pcid).await;
        let b_id = *b.swarm.local_peer_id();
        put_private_channel(&a.storage, pcid);
        let w = wallet();
        a.storage.add_channel_member(pcid, &w.addr, 1, "member").unwrap();
        a.storage.put_local_channel_home_for_test(pcid, &w.addr, 0, 0).unwrap();
        // The stale kick lands.
        a.storage.remove_channel_member_and_raise_epoch_floor(pcid, &w.addr).unwrap();
        assert!(!reconcile::is_channel_member(&a.storage, pcid, &w.addr));
        let claim = private_channel_sync::WalletAuthClaim { timestamp: now_ms(), signature: vec![0; 64], device: None };
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim), true);
        assert_eq!(a.pending_private_channel_sync_requests.len(), 1, "healing walk dispatched");
        let (&id, _) = a.pending_private_channel_sync_requests.iter().next().unwrap();
        let page = private_channel_sync::PrivateChannelSyncResponse {
            has_more: true,
            server_capped: false,
            meta_phase: true,
            meta_has_more: true,
            meta_next_cursor: Some(reconcile::MetaCursor { tier: 1, ts: now_ms() - 1_000, msg_id: [5; 32] }),
            ..private_channel_sync::capped_response(pcid)
        };
        a.handle_private_channel_sync_event(Event::Message {
            peer: b_id,
            message: Message::Response { request_id: id, response: page },
            connection_id: libp2p::swarm::ConnectionId::new_unchecked(0),
        });
        assert!(a.storage.private_channel_sync_resume_raw(&w.addr, pcid).is_some(), "its progress is persisted");
        // A wallet with no stake at all is still never dispatched for.
        let stranger = wallet();
        let claim = private_channel_sync::WalletAuthClaim { timestamp: now_ms(), signature: vec![0; 64], device: None };
        let before = a.pending_private_channel_sync_requests.len();
        a.maybe_trigger_private_channel_sync(pcid, &stranger.addr, Some(claim), true);
        assert_eq!(a.pending_private_channel_sync_requests.len(), before);
    }

    #[tokio::test]
    async fn unsubscribe_waits_for_an_in_flight_private_sync_session() {
        let pcid = (1u64 << 40) + 9;
        let (mut a, _da, _b, _db) = connected_pair_subscribed(pcid).await;
        put_private_channel(&a.storage, pcid);
        a.subscribe_channel(pcid);
        let w = wallet();
        a.storage.add_channel_member(pcid, &w.addr, 1, "member").unwrap();
        let claim = private_channel_sync::WalletAuthClaim { timestamp: now_ms(), signature: vec![0; 64], device: None };
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim), true);
        assert_eq!(a.pending_private_channel_sync_requests.len(), 1);
        put_lifecycle_row(&a.storage, pcid);
        a.reconcile_channel_lifecycle(pcid);
        assert!(a.topics.is_channel_subscribed(pcid), "deferred while the session runs");
        // Session ends (release path) → the deferred unsubscribe applies.
        a.pending_private_channel_sync_requests.clear();
        a.release_private_channel_sync_trigger_if_no_siblings(&w.addr, pcid);
        assert!(!a.topics.is_channel_subscribed(pcid));
        assert!(a.lifecycle_unsubscribed.contains(&pcid));
    }

    /// l2-node 0.149.0 (plan §6): a wallet that is no longer a member is
    /// never dispatched for (no request, no throttle stamp).
    #[tokio::test]
    async fn private_sync_is_not_dispatched_for_a_non_member() {
        let pcid = (1u64 << 40) + 31;
        let (mut a, _da, _b, _db) = connected_pair_subscribed(pcid).await;
        put_private_channel(&a.storage, pcid);
        let w = wallet();
        let key = (w.addr.clone(), pcid);
        let claim = private_channel_sync::WalletAuthClaim { timestamp: now_ms(), signature: vec![0; 64], device: None };
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim.clone()), true);
        assert!(a.pending_private_channel_sync_requests.is_empty(), "non-member: nothing sent");
        assert!(a.private_channel_sync_throttle.entry(&key).is_none(), "and nothing stamped");
        assert!(!a.private_channel_sync_triggered.contains(&key));
        // Positive control: the same call once the wallet is a member.
        a.storage.add_channel_member(pcid, &w.addr, 1, "member").unwrap();
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim), true);
        assert_eq!(a.pending_private_channel_sync_requests.len(), 1);
    }

    /// l2-node 0.149.0 (plan §6): the requester writes the resume row after
    /// an applied page, a `server_capped` answer leaves it as it was, the
    /// next session continues with ONE request to the same (connected)
    /// peer from the stored cursor, and a row naming another peer is never
    /// followed (fresh walk).
    #[tokio::test]
    async fn private_sync_persists_and_resumes_with_the_same_peer_only() {
        use libp2p::request_response::{Event, Message};
        let pcid = (1u64 << 40) + 33;
        let (mut a, _da, b, _db) = connected_pair_subscribed(pcid).await;
        let b_id = *b.swarm.local_peer_id();
        put_private_channel(&a.storage, pcid);
        let w = wallet();
        a.storage.add_channel_member(pcid, &w.addr, 1, "member").unwrap();
        let key = (w.addr.clone(), pcid);
        let claim = private_channel_sync::WalletAuthClaim { timestamp: now_ms(), signature: vec![0; 64], device: None };
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim.clone()), true);
        let (&id, pending) = a.pending_private_channel_sync_requests.iter().next().unwrap();
        assert_eq!(pending.peer_id, b_id);
        assert_eq!(pending.session, private_channel_sync::SyncSession::default(), "first walk starts fresh");
        let respond = |a: &mut NetworkService, request_id, response| {
            a.handle_private_channel_sync_event(Event::Message {
                peer: b_id,
                message: Message::Response { request_id, response },
                connection_id: libp2p::swarm::ConnectionId::new_unchecked(0),
            });
        };
        // A metadata page with more to come → row written, continuation sent.
        let c1 = reconcile::MetaCursor { tier: 1, ts: now_ms() - 1_000, msg_id: [5; 32] };
        let page = private_channel_sync::PrivateChannelSyncResponse {
            has_more: true,
            server_capped: false,
            meta_phase: true,
            meta_has_more: true,
            meta_next_cursor: Some(c1.clone()),
            ..private_channel_sync::capped_response(pcid)
        };
        respond(&mut a, id, page.clone());
        let row = |a: &NetworkService| {
            private_channel_sync::decode_resume_row(
                &a.storage.private_channel_sync_resume_raw(&w.addr, pcid).expect("row written"),
                now_ms(),
            )
            .expect("row validates")
        };
        let r = row(&a);
        assert_eq!(r.phase, Some(private_channel_sync::ResumePhase::Meta));
        assert_eq!(r.meta_cursor, Some(c1.clone()));
        assert_eq!((r.peer.as_str(), r.sessions), (b_id.to_string().as_str(), 1));
        // The continuation is capped (budget gone): the row is unchanged.
        let (&id2, _) = a.pending_private_channel_sync_requests.iter().next().unwrap();
        respond(&mut a, id2, private_channel_sync::capped_response(pcid));
        assert_eq!(row(&a), r, "a refused page writes nothing");
        assert!(a.pending_private_channel_sync_requests.is_empty());
        // Next session (gate reopened): one request to the same peer, seeded.
        a.private_channel_sync_throttle.on_complete(&key);
        a.private_channel_sync_triggered.clear();
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim.clone()), true);
        assert_eq!(a.pending_private_channel_sync_requests.len(), 1);
        let pending = a.pending_private_channel_sync_requests.values().next().unwrap();
        assert_eq!(pending.peer_id, b_id);
        assert_eq!(pending.session.last_meta_cursor, Some(c1));
        assert_eq!(pending.resume.as_ref().map(|s| s.sessions), Some(2));
        assert!(pending.same_peer_resume);
        assert_eq!(a.counters.private_sync_resumed_sessions.load(Ordering::Relaxed), 1);
        // Round 2: the stored peer refuses the continuation (budget still
        // refilling): ONE stall, the walk and its position are kept.
        let (&rid, _) = a.pending_private_channel_sync_requests.iter().next().unwrap();
        respond(&mut a, rid, private_channel_sync::capped_response(pcid));
        let kept = row(&a);
        assert_eq!((kept.phase, kept.meta_cursor.clone(), kept.stalls), (r.phase, r.meta_cursor.clone(), 1));
        // After the refill the next session resumes with the same peer; its
        // page only moves the cursor (no envelope): neutral — the walk
        // continues and the stall count is neither reset nor raised.
        let redispatch = |a: &mut NetworkService| {
            a.pending_private_channel_sync_requests.clear();
            a.private_channel_sync_throttle.on_complete(&key);
            a.private_channel_sync_triggered.clear();
            a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim.clone()), true);
            let (&id, p) = a.pending_private_channel_sync_requests.iter().next().unwrap();
            (id, p.same_peer_resume)
        };
        let (rid, same) = redispatch(&mut a);
        assert!(same, "walk kept → same-peer continuation");
        let c2 = reconcile::MetaCursor { tier: 1, ts: now_ms() - 500, msg_id: [6; 32] };
        let page2 = private_channel_sync::PrivateChannelSyncResponse {
            meta_next_cursor: Some(c2.clone()),
            ..page.clone()
        };
        respond(&mut a, rid, page2);
        let advanced = row(&a);
        assert_eq!((advanced.meta_cursor.clone(), advanced.stalls), (Some(c2), 1), "a bare cursor move is neutral");
        // Its continuation finishes the walk naturally: phase cleared.
        let (&cid2, _) = a.pending_private_channel_sync_requests.iter().next().unwrap();
        let last_meta = private_channel_sync::PrivateChannelSyncResponse { meta_has_more: false, meta_next_cursor: None, ..page.clone() };
        respond(&mut a, cid2, last_meta);
        let (&cid3, _) = a.pending_private_channel_sync_requests.iter().next().unwrap();
        let last_chat = private_channel_sync::PrivateChannelSyncResponse { server_capped: false, ..private_channel_sync::capped_response(pcid) };
        respond(&mut a, cid3, last_chat);
        assert_eq!(row(&a).phase, None, "walk completed after the refill");
        // Three CONSECUTIVE stalls of a same-peer continuation → fanout.
        a.storage
            .put_private_channel_sync_resume(&w.addr, pcid, &serde_json::to_vec(&r).unwrap())
            .unwrap();
        for n in 1..=private_channel_sync::MAX_RESUME_STALLS {
            let (rid, same) = redispatch(&mut a);
            assert!(same, "stall {n}: still the same peer");
            respond(&mut a, rid, private_channel_sync::capped_response(pcid));
        }
        assert_eq!(row(&a).phase, None, "walk abandoned after the stall cap");
        let (_, same) = redispatch(&mut a);
        assert!(!same, "next session fans out");
        a.pending_private_channel_sync_requests.clear();
        // A row naming a peer that is not connected is never followed.
        let foreign = private_channel_sync::ResumeRow { peer: PeerId::random().to_string(), ..r };
        a.storage
            .put_private_channel_sync_resume(&w.addr, pcid, &serde_json::to_vec(&foreign).unwrap())
            .unwrap();
        a.pending_private_channel_sync_requests.clear();
        a.private_channel_sync_throttle.on_complete(&key);
        a.private_channel_sync_triggered.clear();
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(claim), true);
        let pending = a.pending_private_channel_sync_requests.values().next().unwrap();
        assert_eq!(pending.session, private_channel_sync::SyncSession::default(), "no foreign cursor");
        assert!(!pending.same_peer_resume, "a fanout continuation from our own (empty) position");
        // 1 + the post-refill resume + three stalled resumes + the foreign
        // row's fanout continuation (a resume of the walk, from our own
        // position).
        assert_eq!(a.counters.private_sync_resumed_sessions.load(Ordering::Relaxed), 6);
    }

    // ---- l2-node 0.150.0 (Phase E): HOMES-keyed private-sync backfill ----

    fn fresh_claim() -> private_channel_sync::WalletAuthClaim {
        private_channel_sync::WalletAuthClaim { timestamp: now_ms(), signature: vec![0; 64], device: None }
    }

    fn put_fed(s: &Storage, w: &str, cid: u64) {
        s.put_cf(schema::cf::LOCAL_CHANNEL_FED, &schema::encode_local_channel_fed_key(w, cid), &now_ms().to_be_bytes())
            .unwrap();
    }

    fn homes_evaluated(a: &NetworkService) -> u64 {
        a.counters.private_sync_homes_pairs_evaluated.load(Ordering::Relaxed)
    }

    #[tokio::test]
    async fn claim_refresh_caches_and_triggers_for_a_homes_only_wallet() {
        let pcid = (1u64 << 40) + 60;
        let (mut a, _da, b, _db) = connected_pair_subscribed(pcid).await;
        let b_id = *b.swarm.local_peer_id();
        put_private_channel(&a.storage, pcid);
        let w = wallet();
        a.storage.add_channel_member(pcid, &w.addr, 1, "member").unwrap();
        a.storage.put_local_channel_home_for_test(pcid, &w.addr, 1, 1).unwrap();
        a.refresh_private_channel_sync_claim(&w.addr, Some(fresh_claim()));
        assert!(a.private_channel_sync_wallet_claims.contains_key(&w.addr), "claim cached (N3: union non-empty)");
        assert_eq!(a.pending_private_channel_sync_requests.len(), 1, "dispatched");
        assert_eq!(a.pending_private_channel_sync_requests.values().next().unwrap().peer_id, b_id);
        assert_eq!(homes_evaluated(&a), 1);
        // The cancel path (`record_local_channel_home_for`: channel id, no
        // claim) now dispatches for this wallet off the cached claim.
        let key = (w.addr.clone(), pcid);
        a.pending_private_channel_sync_requests.clear();
        a.private_channel_sync_triggered.clear();
        a.private_channel_sync_throttle.on_complete(&key);
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, None, false);
        assert_eq!(a.pending_private_channel_sync_requests.len(), 1, "cancel-triggered sync dispatched");
        // A wallet with neither FED nor HOMES rows: nothing cached.
        let other = wallet();
        a.refresh_private_channel_sync_claim(&other.addr, Some(fresh_claim()));
        assert!(!a.private_channel_sync_wallet_claims.contains_key(&other.addr));
    }

    #[tokio::test]
    async fn a_channel_in_both_sources_triggers_once_and_each_source_is_capped() {
        let pcid = (1u64 << 40) + 61;
        let (mut a, _da, _b, _db) = connected_pair_subscribed(pcid).await;
        put_private_channel(&a.storage, pcid);
        let w = wallet();
        a.storage.add_channel_member(pcid, &w.addr, 1, "member").unwrap();
        a.storage.put_local_channel_home_for_test(pcid, &w.addr, 1, 1).unwrap();
        put_fed(&a.storage, &w.addr, pcid);
        assert_eq!(a.private_sync_refresh_channels(&w.addr).len(), 1, "deduplicated by channel id");
        a.refresh_private_channel_sync_claim(&w.addr, Some(fresh_claim()));
        assert_eq!(a.pending_private_channel_sync_requests.len(), 1, "one dispatch for the pair");
        // Caps: 300 FED-only + 300 HOMES-only channels → 256 + 256.
        let v = wallet();
        for i in 0..300u64 {
            put_fed(&a.storage, &v.addr, (1u64 << 40) + 1_000 + i);
            a.storage.put_local_channel_home_for_test((1u64 << 40) + 5_000 + i, &v.addr, 1, 1).unwrap();
        }
        let set = a.private_sync_refresh_channels(&v.addr);
        assert_eq!(set.len(), 2 * MAX_CLAIM_REFRESH_CHANNELS, "a full FED source does not starve HOMES");
        assert_eq!(set.iter().filter(|c| **c >= (1u64 << 40) + 5_000).count(), MAX_CLAIM_REFRESH_CHANNELS);
    }

    /// Round-1 audit W1: the no-host gate walks gossipsub's peer table once
    /// per claim refresh / sweep tick, not once per channel, and never for
    /// a pair the in-flight set or the throttle already holds back.
    #[tokio::test]
    async fn a_refresh_over_many_channels_walks_the_peer_table_once() {
        let (mut a, _da, _b, _db) = connected_pair().await;
        let w = wallet();
        for i in 0..20u64 {
            let cid = (1u64 << 40) + 200 + i;
            put_private_channel(&a.storage, cid);
            a.storage.add_channel_member(cid, &w.addr, 1, "member").unwrap();
            a.storage.put_local_channel_home_for_test(cid, &w.addr, 1, 1).unwrap();
        }
        a.refresh_private_channel_sync_claim(&w.addr, Some(fresh_claim()));
        assert_eq!(a.remote_subscriber_walks, 1, "one walk for 20 channels");
        assert_eq!(a.counters.private_sync_skipped_no_host.load(Ordering::Relaxed), 20);
        // One sweep tick: one more walk.
        a.private_channel_sync_config.catchup_batch_size = 100;
        a.retry_incomplete_private_channel_syncs_homes();
        assert_eq!(a.remote_subscriber_walks, 2, "one walk per sweep tick");
        // A pair the throttle holds back never reaches the gate.
        let cid = (1u64 << 40) + 200;
        let key = (w.addr.clone(), cid);
        a.private_channel_sync_throttle.on_dispatch(key, Instant::now(), 0.0);
        a.maybe_trigger_private_channel_sync(cid, &w.addr, None, false);
        assert_eq!(a.remote_subscriber_walks, 2, "throttled: no walk");
        // A single trigger (cancel path) builds its own snapshot.
        let other = (1u64 << 40) + 201;
        a.maybe_trigger_private_channel_sync(other, &w.addr, None, false);
        assert_eq!(a.remote_subscriber_walks, 3);
    }

    #[tokio::test]
    async fn the_no_host_gate_skips_non_federated_pairs_without_moving_the_throttle() {
        let (mut a, _da, _b, _db) = connected_pair().await;
        let pcid = (1u64 << 40) + 62;
        put_private_channel(&a.storage, pcid);
        let w = wallet();
        a.storage.add_channel_member(pcid, &w.addr, 1, "member").unwrap();
        a.storage.put_local_channel_home_for_test(pcid, &w.addr, 1, 1).unwrap();
        let key = (w.addr.clone(), pcid);
        // A connected peer exists, but nobody subscribes the channel.
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(fresh_claim()), true);
        assert!(a.pending_private_channel_sync_requests.is_empty(), "no host: nothing sent");
        assert!(a.private_channel_sync_throttle.entry(&key).is_none(), "no throttle stamp");
        assert!(!a.private_channel_sync_triggered.contains(&key));
        assert_eq!(a.counters.private_sync_skipped_no_host.load(Ordering::Relaxed), 1);
        // A federated pair keeps the connected-peer fallback.
        put_fed(&a.storage, &w.addr, pcid);
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(fresh_claim()), true);
        assert_eq!(a.pending_private_channel_sync_requests.len(), 1, "FED pair: fallback to a connected peer");
        assert_eq!(a.counters.private_sync_skipped_no_host.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_non_federated_pair_asks_only_subscribed_peers() {
        let pcid = (1u64 << 40) + 63;
        let (mut a, _da, mut b, _db) = connected_pair().await;
        // A third node, connected to `a` but NOT subscribed.
        let (mut c, _dc) = service().await;
        let c_id = *c.swarm.local_peer_id();
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = c.swarm.select_next_some().await {
                if address.to_string().starts_with("/ip4/127.0.0.1/tcp/") {
                    break address;
                }
            }
        };
        a.swarm.dial(addr).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while !a.swarm.is_connected(&c_id) {
            assert!(tokio::time::Instant::now() < deadline, "loopback connection timed out");
            tokio::select! {
                _ = a.swarm.select_next_some() => {}
                _ = b.swarm.select_next_some() => {}
                _ = c.swarm.select_next_some() => {}
            }
        }
        subscribe_remote(&mut a, &mut b, pcid).await;
        let b_id = *b.swarm.local_peer_id();
        // `a` is not on the topic itself: `b` is a subscriber, not a mesh peer.
        put_private_channel(&a.storage, pcid);
        let topic_hash = libp2p::gossipsub::IdentTopic::new(gossip::channel_topic(a.topics.network_id(), pcid)).hash();
        assert_eq!(a.swarm.behaviour().gossipsub.mesh_peers(&topic_hash).count(), 0);
        let w = wallet();
        a.storage.add_channel_member(pcid, &w.addr, 1, "member").unwrap();
        a.storage.put_local_channel_home_for_test(pcid, &w.addr, 1, 1).unwrap();
        a.maybe_trigger_private_channel_sync(pcid, &w.addr, Some(fresh_claim()), true);
        let peers: Vec<PeerId> = a.pending_private_channel_sync_requests.values().map(|p| p.peer_id).collect();
        assert_eq!(peers, vec![b_id], "only the subscribed peer, never the unsubscribed connected one");
    }

    #[tokio::test]
    async fn the_homes_sweep_prefilters_on_the_claim_skips_fed_and_wraps() {
        let pcid = (1u64 << 40) + 64;
        let (mut a, _da, _b, _db) = connected_pair_subscribed(pcid).await;
        a.private_channel_sync_config.catchup_batch_size = 2;
        put_private_channel(&a.storage, pcid);
        let (w1, w2, w3) = (wallet(), wallet(), wallet());
        for w in [&w1, &w2, &w3] {
            a.storage.add_channel_member(pcid, &w.addr, 1, "member").unwrap();
            a.storage.put_local_channel_home_for_test(pcid, &w.addr, 1, 1).unwrap();
        }
        // No cached claim for anyone: every key skipped before any per-key
        // storage read (the evaluated counter stays 0); the cursor advances
        // (2 keys) and then wraps (1 key < batch).
        a.retry_incomplete_private_channel_syncs_homes();
        assert_eq!(homes_evaluated(&a), 0, "no claim → no storage read per key");
        let c1 = a
            .storage
            .get_cf(schema::cf::NODE_STATE, schema::state_keys::PRIVATE_CHANNEL_SYNC_HOMES_RETRY_CURSOR)
            .unwrap()
            .unwrap();
        assert!(!c1.is_empty(), "cursor advanced");
        a.retry_incomplete_private_channel_syncs_homes();
        let c2 = a
            .storage
            .get_cf(schema::cf::NODE_STATE, schema::state_keys::PRIVATE_CHANNEL_SYNC_HOMES_RETRY_CURSOR)
            .unwrap()
            .unwrap();
        assert!(c2.is_empty(), "cursor wrapped at the end of the index");
        assert!(a.pending_private_channel_sync_requests.is_empty());
        // Claims cached for all three; w1 is also federated (the FED sweep's
        // job): only w2 and w3 are dispatched by the HOMES sweep.
        for w in [&w1, &w2, &w3] {
            a.cache_private_channel_sync_claim(&w.addr, fresh_claim());
        }
        put_fed(&a.storage, &w1.addr, pcid);
        a.private_channel_sync_config.catchup_batch_size = 10;
        a.retry_incomplete_private_channel_syncs_homes();
        assert_eq!(homes_evaluated(&a), 3);
        let mut sent: Vec<String> = a.pending_private_channel_sync_requests.values().map(|p| p.wallet.clone()).collect();
        sent.sort();
        let mut want = vec![w2.addr.clone(), w3.addr.clone()];
        want.sort();
        assert_eq!(sent, want, "FED-covered key skipped");
        // An orphan index entry (no HOMES row) is never acted on.
        let orphan = wallet();
        a.cache_private_channel_sync_claim(&orphan.addr, fresh_claim());
        a.storage.add_channel_member(pcid, &orphan.addr, 1, "member").unwrap();
        a.storage
            .put_cf(
                schema::cf::LOCAL_CHANNEL_HOMES_BY_WALLET,
                &schema::encode_local_channel_home_wallet_key(orphan.addr.as_bytes(), pcid),
                &[],
            )
            .unwrap();
        a.retry_incomplete_private_channel_syncs_homes();
        assert!(
            !a.pending_private_channel_sync_requests.values().any(|p| p.wallet == orphan.addr),
            "the index is only a candidate set"
        );
    }

}

#[cfg(test)]
mod backfill_0152_tests;

#[cfg(test)]
mod backfill_0153_tests;

#[cfg(test)]
mod backfill_0151_tests {
    //! l2-node 0.151.0: receiver-side binding of synced DeletionRequests
    //! (G5) and the identity-pull sampling of backfilled authors (G9).
    use super::*;
    use crate::crypto::{self, signing};
    use crate::messages::types::{ChatMessagePayload, DeletionRequestPayload, DeletionType, MessageType};
    use crate::storage::identity::IdentityResolver;
    use tempfile::TempDir;

    fn router() -> (MessageRouter, Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        let r = MessageRouter::new(
            storage.clone(),
            identity,
            None,
            "testnet".to_string(),
            usize::MAX,
            Arc::new(crate::metrics::counters::NetworkCounters::new()),
            crate::config::RateLimitsConfig::default(),
        );
        (r, storage, dir)
    }

    fn signed(sk: &ed25519_dalek::SigningKey, msg_type: MessageType, payload: Vec<u8>, ts: u64) -> (Vec<u8>, [u8; 32]) {
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let msg_id = crypto::compute_msg_id("testnet", &sk.verifying_key().to_bytes(), &payload, ts);
        let sig = signing::sign_ogmara_message(
            sk, "testnet", crate::messages::envelope::PROTOCOL_VERSION, msg_type as u8, &msg_id, ts, &payload,
        );
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type,
            msg_id,
            author,
            timestamp: ts,
            lamport_ts: 0,
            payload,
            signature: sig.to_bytes().to_vec(),
            relay_path: vec![],
        };
        (rmp_serde::to_vec_named(&env).unwrap(), msg_id)
    }

    fn chat(sk: &ed25519_dalek::SigningKey, channel_id: u64, ts: u64) -> (Vec<u8>, [u8; 32]) {
        let p = ChatMessagePayload {
            channel_id,
            content: format!("hello {ts}"),
            content_rating: Default::default(),
            reply_to: None,
            mentions: vec![],
            attachments: vec![],
            enc_content: None,
            enc_nonce: None,
            key_epoch: None,
            buttons: vec![],
            via_button: false,
        };
        signed(sk, MessageType::ChatMessage, rmp_serde::to_vec_named(&p).unwrap(), ts)
    }

    fn deletion(sk: &ed25519_dalek::SigningKey, target: Option<[u8; 32]>, kind: DeletionType, ts: u64) -> Vec<u8> {
        let p = DeletionRequestPayload { delete_type: kind, target_id: target };
        signed(sk, MessageType::DeletionRequest, rmp_serde::to_vec_named(&p).unwrap(), ts).0
    }

    fn now() -> u64 {
        crate::util::now_ms()
    }

    #[test]
    fn deletion_request_is_bound_to_the_synced_scope() {
        let (r, storage, _d) = router();
        let sk = crypto::generate_keypair();
        let t = now();
        let (raw, id) = chat(&sk, 7, t);
        assert!(matches!(r.process_synced_message(&raw), RouteResult::Accepted { .. }));
        let req = deletion(&sk, Some(id), DeletionType::SingleMessage, t + 1);
        assert_eq!(deletion_request_fit(&storage, &req, DeletionScope::Channel(7), 0), DeletionFit::Fits);
        assert_eq!(deletion_request_fit(&storage, &req, DeletionScope::Channel(8), 0), DeletionFit::Neutral, "other channel");
        assert_eq!(deletion_request_fit(&storage, &req, DeletionScope::News, 0), DeletionFit::Neutral, "chat target via news-sync");
        assert_eq!(deletion_request_fit(&storage, &req, DeletionScope::Dm, 0), DeletionFit::Neutral, "chat target via dm-sync");
        // Unknown target: accepted (it becomes a pending row that hides nothing).
        let unknown = deletion(&sk, Some([0xEE; 32]), DeletionType::SingleMessage, t + 2);
        for scope in [DeletionScope::Channel(7), DeletionScope::News, DeletionScope::Dm] {
            assert_eq!(deletion_request_fit(&storage, &unknown, scope, 0), DeletionFit::Fits);
        }
        // AllUserContent is never served by any backfill.
        let all = deletion(&sk, None, DeletionType::AllUserContent, t + 3);
        assert_eq!(deletion_request_fit(&storage, &all, DeletionScope::News, 0), DeletionFit::Neutral);
        // Other types are not this check's business.
        assert_eq!(deletion_request_fit(&storage, &raw, DeletionScope::News, 0), DeletionFit::Fits);
        // Out of window → neutral; a broken payload → malformed (taint).
        assert_eq!(deletion_request_fit(&storage, &unknown, DeletionScope::News, u64::MAX), DeletionFit::Neutral);
        let broken = signed(&sk, MessageType::DeletionRequest, vec![0xC1, 0xFF], t + 4).0;
        assert_eq!(deletion_request_fit(&storage, &broken, DeletionScope::News, 0), DeletionFit::Malformed);
        assert_eq!(deletion_request_fit(&storage, b"not an envelope", DeletionScope::News, 0), DeletionFit::Malformed);
    }

    #[test]
    fn backfilled_author_sample_is_bounded_deduped_and_allow_listed() {
        let mut out = Vec::new();
        note_backfilled_author(&mut out, "klv1a".into(), MessageType::ChatMessage as u8);
        note_backfilled_author(&mut out, "klv1a".into(), MessageType::NewsPost as u8);
        note_backfilled_author(&mut out, "klv1b".into(), MessageType::ChatEdit as u8);
        assert_eq!(out, vec![("klv1a".to_string(), MessageType::ChatMessage as u8)]);
        for i in 0..1_000 {
            note_backfilled_author(&mut out, format!("klv1x{i}"), MessageType::NewsComment as u8);
        }
        assert_eq!(out.len(), MAX_BACKFILLED_AUTHORS_PER_PAGE);
    }

    /// G9: the reconcile tally samples the author of every newly ACCEPTED
    /// author-facing envelope (not duplicates), for the identity-pull gate.
    #[test]
    fn reconcile_tally_samples_accepted_authors() {
        let (r, storage, _d) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let t = now();
        let (a, _) = chat(&sk, 3, t);
        let (b, _) = chat(&sk, 3, t + 1);
        let peer = PeerId::random();
        let mut authors = Vec::new();
        let tally = tally_reconcile_envelopes(&r, &storage, &peer, 3, &[a.clone(), b], 10, 0, &mut authors);
        assert_eq!(tally.newly_accepted, 2);
        assert_eq!(authors, vec![(author, MessageType::ChatMessage as u8)]);
        // A page of duplicates samples nobody.
        let mut again = Vec::new();
        tally_reconcile_envelopes(&r, &storage, &peer, 3, &[a], 10, 0, &mut again);
        assert!(again.is_empty());
    }

    /// W1/W4: a DeletionRequest accepted only as a pending row, or one the
    /// router refuses, or one outside this sync's window, is neither
    /// progress (newly_accepted / admitted) nor taint — and a page of
    /// verified duplicates plus such requests still proves "in sync".
    #[test]
    fn deletion_requests_are_neither_progress_nor_taint() {
        let (r, storage, _d) = router();
        let sk = crypto::generate_keypair();
        let wallet = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        storage
            .put_cf(
                crate::storage::schema::cf::USERS,
                wallet.as_bytes(),
                serde_json::json!({"address": wallet, "registered_at": 1_000}).to_string().as_bytes(),
            )
            .unwrap();
        let t = now();
        let (kept, _) = chat(&sk, 5, t);
        assert!(matches!(r.process_synced_message(&kept), RouteResult::Accepted { .. }));
        let pending = deletion(&sk, Some([0xD1; 32]), DeletionType::SingleMessage, t + 1);
        let out_of_window = deletion(&sk, Some([0xD2; 32]), DeletionType::SingleMessage, t - 10_000);
        // A request the router refuses: a stranger's known message.
        let stranger = crypto::generate_keypair();
        let (theirs, their_id) = chat(&stranger, 5, t + 2);
        assert!(matches!(r.process_synced_message(&theirs), RouteResult::Accepted { .. }));
        let refused = deletion(&sk, Some(their_id), DeletionType::SingleMessage, t + 3);
        let peer = PeerId::random();
        let mut authors = Vec::new();
        let tally = tally_reconcile_envelopes(
            &r,
            &storage,
            &peer,
            5,
            &[kept.clone(), pending.clone(), out_of_window, refused],
            10,
            t - 1_000, // this sync's window start
            &mut authors,
        );
        assert_eq!(tally.newly_accepted, 0);
        assert_eq!(tally.admitted, 1, "only the verified duplicate");
        assert_eq!(tally.verified_dups, 1);
        assert_eq!(tally.ignored_deletions, 3);
        assert!(!tally.tainted);
        assert!(tally.is_verified_in_sync_page(4, false));
        assert!(storage.message_exists(&rmp_serde::from_slice::<Envelope>(&pending).unwrap().msg_id).unwrap());
        // W-B: an INVALID DeletionRequest (forged signature) taints; a
        // malformed one is dropped and taints too.
        let mut forged_env = rmp_serde::from_slice::<Envelope>(&deletion(&sk, Some([0xD4; 32]), DeletionType::SingleMessage, t + 5)).unwrap();
        forged_env.signature = vec![7u8; 64];
        let forged = rmp_serde::to_vec_named(&forged_env).unwrap();
        let mut a2 = Vec::new();
        let tally = tally_reconcile_envelopes(&r, &storage, &peer, 5, &[forged], 10, 0, &mut a2);
        assert!(tally.tainted, "an Invalid 0x50 taints");
        assert_eq!(tally.ignored_deletions, 0);
        let broken = signed(&sk, MessageType::DeletionRequest, vec![0xC1], t + 6).0;
        let tally = tally_reconcile_envelopes(&r, &storage, &peer, 5, &[broken], 10, 0, &mut a2);
        assert!(tally.tainted && tally.cross_channel_dropped == 1, "a malformed 0x50 taints");
        // A page of ONLY ignorable requests is no in-sync evidence.
        let only = ReconcileTally { ignored_deletions: 2, ..Default::default() };
        assert!(!only.is_verified_in_sync_page(2, false));
    }

    /// The requester's oversized-page guard now admits a full page plus
    /// the ride-alongs (pre-0.151.0 it refused anything above the primary
    /// cap, discarding every busy channel's first / last page whole).
    #[test]
    fn page_with_ride_alongs_is_verified_not_refused() {
        let (r, storage, _d) = router();
        let sk = crypto::generate_keypair();
        let t = now();
        let envs: Vec<Vec<u8>> = (0..5).map(|i| chat(&sk, 4, t + i).0).collect();
        let peer = PeerId::random();
        let mut authors = Vec::new();
        // Primary cap 3, but meta/edit ride-alongs may legitimately add more.
        let tally = tally_reconcile_envelopes(
            &r, &storage, &peer, 4, &envs, reconcile::max_page_with_ride_alongs(3), 0, &mut authors,
        );
        assert!(!tally.tainted);
        assert_eq!(tally.newly_accepted, 5);
        assert!(news_sync::MAX_ENVELOPES_PER_PAGE_WITH_RIDE_ALONGS > news_sync::MAX_ENVELOPES_PER_RESPONSE);
        assert!(dm_sync::MAX_ENVELOPES_PER_PAGE_WITH_RIDE_ALONGS > dm_sync::MAX_ENVELOPES_PER_RESPONSE);
    }
}
