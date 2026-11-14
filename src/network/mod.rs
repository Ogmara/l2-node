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
// SOCKS5 dialer shipped ahead of its libp2p transport wiring (onion
// Phase 2, spec 13 §6.4) so the security boundary could be audited on its
// own; only its tests use it until that integration lands.
#[allow(dead_code, reason = "onion Phase 2 transport not wired yet")]
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
    /// Server-side rate-limit state for inbound dm-sync requests (Phase 2).
    dm_sync_limits: Arc<dm_sync::DmResponderLimits>,
    /// Outstanding outbound dm-sync requests → `(peer, wallet)` for race-cancel
    /// + cursor paging of that wallet's backfill.
    pending_dm_sync_requests: HashMap<
        libp2p::request_response::OutboundRequestId,
        DmSyncPending,
    >,
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
}

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
enum ReconcileApplyOutcome {
    Handled,
    NoProgress { verified_in_sync: bool },
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
}

impl ReconcileTally {
    /// The page proves THIS responder offered nothing new: it is the whole
    /// session (`has_more == false`), non-empty, untainted, and every
    /// envelope on it is a byte-verified duplicate.
    fn is_verified_in_sync_page(&self, env_count: usize, has_more: bool) -> bool {
        !has_more
            && env_count > 0
            && !self.tainted
            && self.newly_accepted == 0
            && self.verified_dups == env_count
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
        if !envelope_targets_channel(env_bytes, channel_id) {
            t.cross_channel_dropped += 1;
            t.tainted = true;
            continue;
        }
        match router.process_synced_message(env_bytes) {
            RouteResult::Accepted { .. } => {
                t.admitted += 1;
                t.newly_accepted += 1;
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
    /// completion requires (round 4).
    session: private_channel_sync::SyncSession,
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
#[derive(Debug, Clone)]
pub struct PrivateChannelSyncTrigger {
    /// `Some` = one federated channel (federate call; a fresh claim may
    /// bypass the attempt throttle down to its 60 s floor). `None` = every
    /// private channel in `LOCAL_CHANNEL_FED` for `wallet`, never bypassing.
    pub channel_id: Option<u64>,
    /// The wallet whose membership/backfill this concerns.
    pub wallet: String,
    /// The verified claim, if any (wallet-direct or device-signed).
    pub wallet_claim: Option<private_channel_sync::WalletAuthClaim>,
}

/// Max private channels re-evaluated for one wallet per claim refresh
/// (`PrivateChannelSyncTrigger { channel_id: None, .. }`).
pub const MAX_CLAIM_REFRESH_CHANNELS: usize = 256;

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
        | MessageType::ChannelRemoveModerator => {
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

/// Smuggling defense for dm-sync responses (Phase 2): accept only DM content
/// types (`dm_sync::is_dm_type` — `DirectMessage`/`DirectMessageEdit`/
/// `DirectMessageDelete` as of audit final pre-mainnet W6), so a responder
/// can't inject another type through this path. Every envelope is still
/// signature-validated by `process_synced_message`.
fn envelope_targets_dm(env_bytes: &[u8]) -> bool {
    use crate::messages::envelope::Envelope;
    let envelope: Envelope = match rmp_serde::from_slice(env_bytes) {
        Ok(e) => e,
        Err(_) => return false,
    };
    dm_sync::is_dm_type(envelope.msg_type_u8())
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
            peer_reconcile_health: HashMap::new(),
            sync_limits: Arc::new(reconcile::ResponderLimits::default()),
            pending_sync_requests: HashMap::new(),
            identity_sync_limits: Arc::new(identity_sync::IdentityResponderLimits::default()),
            pending_identity_sync_requests: HashMap::new(),
            identity_sync_triggered: HashSet::new(),
            identity_sync_triggered_order: std::collections::VecDeque::new(),
            news_sync_limits: Arc::new(news_sync::NewsResponderLimits::default()),
            pending_news_sync_requests: HashMap::new(),
            last_news_sync: None,
            dm_config,
            observed_trigger_budget: identity_resync_config.max_observed_triggers_per_interval,
            identity_resync_config,
            dm_sync_limits: Arc::new(dm_sync::DmResponderLimits::default()),
            pending_dm_sync_requests: HashMap::new(),
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

    /// DM retention reaper entry point (audit final pre-mainnet W11). Runs 3
    /// independent, self-contained sweeps, each keyed off timestamp bytes
    /// already present verbatim in the row being examined — never by
    /// re-deriving one CF's delete-key from another CF's decoded content
    /// (identity resolution can change over the retention window; that class
    /// of bug has bitten this campaign before, e.g. W6's
    /// channel_id-from-untrusted-field). `retention_days == 0` means
    /// "unlimited" — disables all three passes, matching the pre-existing
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
                    // duplicate calls are safe.
                    self.subscribe_channel(channel_id);
                    info!(channel_id, "Auto-subscribed to channel topic (chain discovery)");
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
                    // is already deduplication-aware (libp2p drops dial
                    // attempts to peers we're already connected to).
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
                use crate::chain::sc_views::{classify_transport, TransportKind};
                let mut first_addr = None;
                for addr in info.listen_addrs.into_iter().take(16) {
                    if classify_transport(&addr.to_string()) == TransportKind::Unknown {
                        continue; // non-routable — never dial or persist it
                    }
                    if first_addr.is_none() {
                        first_addr = Some(addr.clone());
                    }
                    self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                }
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
        for (_key, value) in &entries {
            let addr_str = match std::str::from_utf8(value) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let addr: Multiaddr = match addr_str.parse() {
                Ok(a) => a,
                Err(_) => continue,
            };

            if let Err(e) = self.swarm.dial(addr.clone()) {
                debug!(addr = %addr, error = %e, "Failed to dial persisted peer");
            } else {
                dialed += 1;
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
                let guard = self.identity_sync_limits.try_acquire(
                    peer,
                    &request.wallet,
                    identity_sync::SERVER_MAX_CONCURRENT_PER_PEER,
                    identity_sync::TOTAL_ENVELOPES_CAP,
                );
                let response = if guard.is_none() {
                    identity_sync::capped_response(&request)
                } else {
                    identity_sync::build_response(
                        &self.storage,
                        &request,
                        identity_sync::MAX_ENVELOPES_PER_RESPONSE,
                    )
                };
                let envelopes_sent = response.envelopes.len();
                if envelopes_sent > 0 {
                    self.identity_sync_limits
                        .add_served(peer, &request.wallet, envelopes_sent as u64);
                }
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

        let window_secs = || {
            if self.backfill_config.news_max_age_days == 0 {
                u64::MAX
            } else {
                self.backfill_config
                    .news_max_age_days
                    .saturating_mul(24 * 3600)
            }
        };

        match event {
            // --- Inbound request: serve recent news (windowed + rate-limited) ---
            Event::Message {
                peer,
                message: Message::Request { request, channel, request_id: _ },
                connection_id: _,
            } => {
                let guard = self.news_sync_limits.try_acquire(
                    peer,
                    news_sync::SERVER_MAX_CONCURRENT_PER_PEER,
                    news_sync::TOTAL_ENVELOPES_CAP,
                );
                let response = if guard.is_none() {
                    news_sync::capped_response()
                } else {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    news_sync::build_response(
                        &self.storage,
                        &request,
                        news_sync::MAX_ENVELOPES_PER_RESPONSE,
                        now_ms,
                        window_secs(),
                    )
                };
                let sent = response.envelopes.len();
                if sent > 0 {
                    self.news_sync_limits.add_served(peer, sent as u64);
                }
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
                if count > news_sync::MAX_ENVELOPES_PER_RESPONSE {
                    warn!(
                        peer = %peer, received = count,
                        expected_max = news_sync::MAX_ENVELOPES_PER_RESPONSE,
                        "news-sync: response exceeds this protocol's own max page size; refusing to verify, treating as unproductive"
                    );
                } else {
                    for env_bytes in response.envelopes {
                        if !envelope_targets_news(&env_bytes) {
                            dropped += 1;
                            continue;
                        }
                        match self.router.process_synced_message(&env_bytes) {
                            RouteResult::Accepted { .. } | RouteResult::Duplicate => admitted += 1,
                            RouteResult::Rejected(reason) | RouteResult::Invalid(reason) => {
                                warn!(peer = %peer, reason = %reason, "news-sync: envelope rejected by router");
                            }
                            // Key-epoch arbitration loss (0.143.0): a sync-path rejection.
                            RouteResult::KeyConflict(_) => {}
                            RouteResult::PowRequired { .. } => {}
                        }
                    }
                }
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
                            max_age_secs: window_secs(),
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
        use crate::messages::router::RouteResult;
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

                let guard = self.dm_sync_limits.try_acquire(
                    peer,
                    dm_sync::SERVER_MAX_CONCURRENT_PER_PEER,
                    dm_sync::TOTAL_ENVELOPES_CAP,
                );
                let response = if guard.is_none() {
                    dm_sync::capped_response()
                } else {
                    let (resp, scanned_all) = dm_sync::build_response(
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
                    resp
                };
                let sent = response.envelopes.len();
                if sent > 0 {
                    self.dm_sync_limits.add_served(peer, sent as u64);
                }
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
                    None => return,
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
                let wallet = pending.wallet.clone();
                self.pending_dm_sync_requests
                    .retain(|_, p| p.peer_id == peer || p.wallet != wallet);

                let count = response.envelopes.len();
                let mut admitted = 0usize;
                let mut dropped = 0usize;
                // Security-audit follow-up on W9: see identity-sync's arm
                // above for the full rationale — refuse to verify ANY
                // envelope in a page that exceeds this protocol's own max
                // page size, treating it as unproductive rather than
                // paying the verification cost.
                if count > dm_sync::MAX_ENVELOPES_PER_RESPONSE {
                    warn!(
                        peer = %peer, wallet = %wallet, received = count,
                        expected_max = dm_sync::MAX_ENVELOPES_PER_RESPONSE,
                        "dm-sync: response exceeds this protocol's own max page size; refusing to verify, treating as unproductive"
                    );
                } else {
                    for env_bytes in response.envelopes {
                        if !envelope_targets_dm(&env_bytes) {
                            dropped += 1;
                            continue;
                        }
                        match self.router.process_synced_message(&env_bytes) {
                            RouteResult::Accepted { .. } | RouteResult::Duplicate => admitted += 1,
                            RouteResult::Rejected(reason) | RouteResult::Invalid(reason) => {
                                warn!(peer = %peer, reason = %reason, "dm-sync: envelope rejected by router");
                            }
                            // Key-epoch arbitration loss (0.143.0): a sync-path rejection.
                            RouteResult::KeyConflict(_) => {}
                            RouteResult::PowRequired { .. } => {}
                        }
                    }
                }
                info!(peer = %peer, wallet = %wallet, received = count, admitted, dropped, has_more = response.has_more, "dm-sync: applied batch");

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
    fn private_channel_sync_claim_usable(&self, claim: &private_channel_sync::WalletAuthClaim) -> bool {
        now_ms().abs_diff(claim.timestamp)
            <= private_channel_sync::WALLET_AUTH_MAX_AGE_SECS.saturating_mul(1000)
            && private_channel_sync::device_claim_unrevoked(&self.storage, Some(claim))
    }

    /// A wallet presented a fresh, verified pchansync claim on an
    /// authenticated REST request or WS connect (l2-node 0.142.0, at most
    /// once per wallet per 60 s — gated in the API layer). Cache it and
    /// re-evaluate every private channel the wallet federated here
    /// (`LOCAL_CHANNEL_FED`, at most `MAX_CLAIM_REFRESH_CHANNELS`) through
    /// the normal attempt throttle and completion due-gate — never the
    /// federate bypass, so an active client cannot defeat the 0.141.0
    /// in-sync recheck interval.
    fn refresh_private_channel_sync_claim(
        &mut self,
        wallet: &str,
        claim: Option<private_channel_sync::WalletAuthClaim>,
    ) {
        let Some(claim) = claim else { return };
        if !self.private_channel_sync_config.enabled {
            return;
        }
        let mut prefix = wallet.as_bytes().to_vec();
        prefix.push(0xFF);
        let rows = match self.storage.prefix_iter_cf(
            crate::storage::schema::cf::LOCAL_CHANNEL_FED,
            &prefix,
            MAX_CLAIM_REFRESH_CHANNELS,
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, %wallet, "private-channel-sync claim refresh: LOCAL_CHANNEL_FED read failed");
                return;
            }
        };
        // N3: a wallet with nothing federated here has nothing to backfill —
        // its claim is not cached at all.
        if rows.is_empty() {
            return;
        }
        self.cache_private_channel_sync_claim(wallet, claim);
        for (key, _) in rows {
            let Some(cid) = key
                .get(prefix.len()..)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map(u64::from_be_bytes)
            else {
                continue;
            };
            // `None`: the cached (freshest) claim is picked up inside.
            self.maybe_trigger_private_channel_sync(cid, wallet, None, false);
        }
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
    fn maybe_trigger_private_channel_sync(
        &mut self,
        channel_id: u64,
        wallet: &str,
        wallet_claim: Option<private_channel_sync::WalletAuthClaim>,
        bypass: bool,
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
        let key = (wallet.to_string(), channel_id);
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
        let attached = wallet_claim.filter(|c| self.private_channel_sync_claim_usable(c));
        let cached = self
            .private_channel_sync_wallet_claims
            .get(wallet)
            .filter(|c| self.private_channel_sync_claim_usable(c))
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

        // Candidate selection: GossipSub mesh peers for this channel's
        // topic; fall back to any connected peer if the mesh is sparse.
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
        if candidates.len() < private_channel_sync::FANOUT {
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
            %wallet, channel_id,
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

        for peer in candidates {
            let request = private_channel_sync::sign_request(
                &self.signing_key,
                &network,
                &peer.to_string(),
                wallet,
                channel_id,
                now,
                max_age_secs,
                None,
                Some(claim.clone()),
            );
            // Walk ALL metadata first (R3-1, raw keyset paging); a responder
            // that predates metadata paging ignores this and answers with
            // its legacy first page.
            let request = private_channel_sync::PrivateChannelSyncRequest {
                meta_paging: true,
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
                    session: private_channel_sync::SyncSession::default(),
                },
            );
        }
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
                    warn!(peer = %peer, wallet = %pending.wallet, channel_id = pending.channel_id, "private-channel-sync: responder rejected our auth");
                    self.release_private_channel_sync_trigger_if_no_siblings(&pending.wallet, pending.channel_id);
                    return;
                }
                if response.server_capped {
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

                let count = response.envelopes.len();
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
                    for env_bytes in &response.envelopes {
                        if !private_channel_sync::envelope_is_private_channel_sync_type(env_bytes)
                            || !envelope_targets_channel(env_bytes, channel_id)
                        {
                            dropped += 1;
                            tainted = true;
                            continue;
                        }
                        match self.router.process_synced_message(env_bytes) {
                            RouteResult::Accepted { .. } => {
                                admitted += 1;
                                accepted += 1;
                            }
                            RouteResult::Duplicate => {
                                admitted += 1;
                                if duplicate_is_verified(&self.storage, env_bytes) {
                                    verified_dups += 1;
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
                info!(peer = %peer, %wallet, channel_id, received = count, admitted, dropped, has_more = response.has_more, "private-channel-sync: applied batch");

                // Two-phase state machine (round 4): per-phase page
                // budgets, strictly advancing cursors, no metadata page
                // after the chat phase started; completion only after the
                // chat phase ends with >= 1 `Accepted` in the session.
                let mut session = pending.session;
                session.record_evidence(verified_dups, tainted);
                let step = session.advance(&response, admitted, accepted);
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
                    private_channel_sync::NextStep::StartChat => Some((None, None, true)),
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
                        } else if session.accepted_total > 0 {
                            self.private_channel_sync_throttle
                                .on_accepted_incomplete(throttle_key, now_instant);
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
                        },
                    );
                    return;
                }
                self.release_private_channel_sync_trigger_if_no_siblings(&wallet, channel_id);
            }
            Event::OutboundFailure { peer, request_id, error, .. } => {
                if let Some(p) = self.pending_private_channel_sync_requests.remove(&request_id) {
                    debug!(peer = %peer, wallet = %p.wallet, channel_id = p.channel_id, error = ?error, "private-channel-sync: outbound failed; siblings may succeed");
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
                        self.maybe_trigger_private_channel_sync(channel_id, wallet, None, false);
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
        for idx in order {
            let (peer, response) = slots[idx].take().expect("each index visited exactly once");
            let trial_pending = ReconcilePending {
                peer_id: peer,
                channel_id,
                pages_fetched: 0,
                consecutive_unproductive_pages: 0,
                total_accepted: 0,
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
                ReconcileApplyOutcome::NoProgress { verified_in_sync } => {
                    trials.push((peer, false));
                    in_sync_trials.push((peer, verified_in_sync));
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
        self.release_reconcile_trigger_if_no_siblings(channel_id);
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
        if response.server_capped {
            debug!(
                peer = %peer,
                channel_id = pending.channel_id,
                "reconcile: peer responded server_capped; ignoring (race siblings may succeed)"
            );
            if release_on_no_progress {
                self.release_reconcile_trigger_if_no_siblings(pending.channel_id);
            }
            return ReconcileApplyOutcome::NoProgress { verified_in_sync: false };
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
            return ReconcileApplyOutcome::NoProgress { verified_in_sync: false };
        }

        let env_count = response.envelopes.len();
        let tally = tally_reconcile_envelopes(
            &self.router,
            &self.storage,
            &peer,
            pending.channel_id,
            &response.envelopes,
            self.backfill_config.max_envelopes_per_response,
        );
        let ReconcileTally { admitted, newly_accepted, cross_channel_dropped, .. } = tally;
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
            return ReconcileApplyOutcome::NoProgress { verified_in_sync: false };
        }
        if consecutive_unproductive_pages >= MAX_CONSECUTIVE_UNPRODUCTIVE_PAGES {
            warn!(peer = %peer, channel_id = pending.channel_id, consecutive_unproductive_pages, "reconcile: peer made no progress for too many consecutive pages; stopping this session");
            self.note_reconcile_accepted_incomplete(pending.channel_id, total_accepted);
            if release_on_no_progress {
                self.release_reconcile_trigger_if_no_siblings(pending.channel_id);
            }
            return ReconcileApplyOutcome::NoProgress { verified_in_sync: false };
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
            return ReconcileApplyOutcome::NoProgress { verified_in_sync: false };
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
                ReconcileApplyOutcome::NoProgress { verified_in_sync: false }
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
            ReconcileApplyOutcome::NoProgress { verified_in_sync }
        }
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
                for msg_bytes in &response.messages {
                    if !envelope_targets_channel(msg_bytes, expected_channel) {
                        cross_channel_dropped += 1;
                        continue;
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
            } => {
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
                if self.identity_resync_config.enabled
                    && self.observed_trigger_budget > 0
                    && !self.identity_sync_triggered.contains(&author)
                    && identity_sync::triggers_identity_check(msg_type as u8)
                    && identity_sync::identity_looks_incomplete(&self.storage, &author)
                {
                    self.observed_trigger_budget -= 1;
                    if self.observed_trigger_budget == 0 {
                        // Logged once per exhaustion (not per subsequent
                        // gossip message — the outer `budget > 0` check
                        // already suppresses those) so an operator can see
                        // the trigger going inert for this interval, rather
                        // than it degrading silently.
                        debug!(
                            sweep_interval_secs = self.identity_resync_config.sweep_interval_secs,
                            "identity-sync: observed-author trigger budget exhausted for this interval"
                        );
                    }
                    self.maybe_trigger_identity_sync(author.clone(), identity_sync::SCOPE_ALL);
                }

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
            channel_id: 1,
            envelopes: (0..n).map(|_| Vec::new()).collect(),
            has_more: false,
            next_cursor: None,
            server_capped: false,
            epoch_root: None,
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
        let (mut a, _da, _b, _db) = connected_pair().await;
        let pcid = (1u64 << 40) + 9;
        a.storage
            .put_cf(schema::cf::CHANNELS, &pcid.to_be_bytes(), br#"{"channel_type":2,"history_visibility":1}"#)
            .unwrap();
        let w = wallet();
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
        assert!(svc.private_channel_sync_claim_usable(&device_claim));
        svc.storage
            .put_cf(schema::cf::DEVICE_REVOCATIONS, dev_addr.as_bytes(), &(now - 5_000).to_be_bytes())
            .unwrap();
        assert!(!svc.private_channel_sync_claim_usable(&device_claim), "device revoked after its delegation");
        assert!(svc.private_channel_sync_claim_usable(&direct));
        let stale = private_channel_sync::WalletAuthClaim { timestamp: now - 400_000, ..direct };
        assert!(!svc.private_channel_sync_claim_usable(&stale), "expired");
    }

    #[tokio::test]
    async fn claim_refresh_dispatches_when_the_gate_is_open_and_keeps_the_freshest() {
        let (mut a, _da, _b, _db) = connected_pair().await;
        let pcid = (1u64 << 40) + 11;
        a.storage
            .put_cf(schema::cf::CHANNELS, &pcid.to_be_bytes(), br#"{"channel_type":2,"history_visibility":1}"#)
            .unwrap();
        let w = wallet();
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
        };
        // Positive control: a comparison trial's first page.
        let out = svc.apply_reconcile_response(pending(0), peer, pages[0].clone(), false);
        assert!(matches!(out, ReconcileApplyOutcome::NoProgress { verified_in_sync: true }));
        // The same page on the direct (continuation) path is not evidence.
        svc.reconcile_triggered.insert(CID);
        let out = svc.apply_reconcile_response(pending(3), peer, pages[0].clone(), true);
        assert!(matches!(out, ReconcileApplyOutcome::NoProgress { verified_in_sync: false }));
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
        };
        let out = svc.apply_reconcile_response(pending, peer, pages[0].clone(), true);
        assert!(matches!(out, ReconcileApplyOutcome::NoProgress { verified_in_sync: false }));
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
}
