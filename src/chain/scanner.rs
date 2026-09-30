//! Klever blockchain scanner — polls for new blocks and processes SC events.
//!
//! Monitors the Ogmara smart contract on Klever mainnet (or testnet) for
//! events like user registrations, channel creation, delegations, etc.
//! Updates local state in RocksDB accordingly (spec 03-l2-node.md section 3.2).
//!
//! Rate-limit aware: uses exponential backoff on HTTP 429 responses and
//! inter-batch delays during catch-up to stay within Klever API quotas.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::KleverConfig;
use crate::storage::rocks::Storage;
use crate::storage::schema::cf;

use super::parser;
use super::types::*;

/// Current Unix time in whole seconds, saturating to 0 on a pre-epoch clock
/// rather than panicking. Shared by every "when was this confirmed/recorded"
/// timestamp in this file.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Minimum delay between batches during catch-up scanning (ms).
const CATCHUP_BATCH_DELAY_MS: u64 = 500;
/// Base backoff on rate limit (ms). Doubled on each consecutive 429.
const BACKOFF_BASE_MS: u64 = 5_000;
/// Maximum backoff cap (ms).
const BACKOFF_MAX_MS: u64 = 120_000;
/// Number of blocks per batch during catch-up.
///
/// The chain cursor only persists after a whole batch succeeds
/// (`poll_blocks`'s `set_chain_cursor` call) — a failure anywhere inside
/// `process_range_paged` (rate limit, transient HTTP/JSON error) discards
/// the batch's progress and the next tick retries it from `start`,
/// re-processing (and re-writing to RocksDB) every event already handled
/// earlier in that attempt. Writes are idempotent so this is correctness-
/// safe, but each retry appends a fresh, uncompressed WAL entry per event
/// regardless of whether the value changed. On a node that regularly falls
/// behind and re-syncs, a 2,000-block unit of retry repeatedly amplified
/// WAL growth far beyond actual live data (observed: a single flush of
/// ~197k duplicate writes collapsing to a 165KB SST). Kept small so a
/// mid-batch failure only re-does a bounded, small amount of already-done
/// work.
const CATCHUP_BATCH_SIZE: u64 = 200;
/// Number of blocks per batch when near chain tip.
///
/// Same retry-amplification exposure as `CATCHUP_BATCH_SIZE` above — this
/// path uses the identical cursor-commit-only-on-full-success logic. Live
/// data from the 0.130.1 fix (which only shrunk `CATCHUP_BATCH_SIZE`) showed
/// WAL still growing at ~43MB/hour with zero "Catch-up scan starting"
/// events in the window — i.e. the amplification was happening entirely
/// through THIS path, not the catch-up one, presumably because the node
/// sits in the "moderately behind, under the catch-up threshold" zone far
/// more of the time than it spends in an actual catch-up burst. Shrunk by
/// the same ~10x factor, same rationale.
const TIP_BATCH_SIZE: u64 = 50;
/// If we're more than this many blocks behind, we're in catch-up mode.
const CATCHUP_THRESHOLD: u64 = 5_000;

/// Self-imposed minimum spacing between outbound Klever API requests (ms).
///
/// Audit 2026-09-28: the old 100ms inter-page sleep in `process_range_paged`
/// allowed ~10 req/s — roughly 40x over the testnet API's documented "15
/// requests in 1m0s" cap — so a catch-up scan reliably drew a 429 partway
/// through a page walk (often well before reaching `MAX_PAGES`), discarding
/// the batch's progress before `PageOutcome`'s cap-exceeded classification
/// could ever run. Reactive exponential backoff after the fact doesn't fix
/// this: it burns the same wasted requests before backing off, every time.
/// Pacing every outbound call proactively at a safe fraction of the known
/// limit avoids the 429 in the first place. 4.5s spacing sustains ~13.3
/// req/min, leaving margin under 15/min for network/response latency.
/// Applied uniformly to every Klever HTTP call this scanner makes
/// (`get_latest_block_height`, `process_range_paged`,
/// `query_channel_id_by_slug`) via `throttle_klever_request` — the 429's
/// error text says "for this endpoint", which may mean independent
/// per-endpoint budgets, but sharing one conservative budget across all of
/// them is the safe assumption absent confirmation either way.
const KLEVER_REQUEST_MIN_SPACING_MS: u64 = 4_500;

/// Minimum time between re-verifying an id that most recently came back
/// `NoOnChainBacking` (audit 2026-09-29 round 3.1). Without this, a
/// handful of standing out-of-range fabricated-public-claim rows — or,
/// with no attacker at all, a legitimate channel mid-on-chain-confirmation
/// — get re-checked and re-`warn!`-alerted on EVERY sweep tick forever,
/// which both wastes the entire per-tick RPC budget (starving the
/// round-robin lane permanently) and turns
/// `CHANNEL_VERIFICATION_ALERTS_TOTAL` into a measure of sweep uptime
/// rather than incidents. One hour comfortably covers a normal on-chain
/// confirmation delay while still cutting re-check volume by ~99.9%
/// relative to the default 300s sweep interval. A genuine on-chain
/// confirmation is never delayed by this — the historical scanner's own
/// `ChannelCreated`/`ChannelTransferred` processing calls
/// `mark_channel_creator_verified` directly, bypassing this cooldown
/// entirely.
const NO_BACKING_RECHECK_COOLDOWN_SECS: u64 = 3_600;

/// Minimum time between re-confirming an id that most recently came back
/// `Confirmed`/`Corrected` (audit round 5, security finding S4). Without
/// this, Lane 3's round-robin spends its budget re-verifying rows that
/// were JUST confirmed (by the historical scanner's own real-time event
/// processing, or an earlier lane pass) exactly as often as it spends it
/// on rows that have never been independently checked at all — the
/// actual squat candidates this whole sweep exists to find. 24 hours is
/// short relative to round-robin's own documented full-cycle time at
/// scale (weeks to years — see CHANGELOG "Round-robin lane is
/// impractical at scale"), so it never meaningfully delays catching a
/// transfer lost to a scan gap; it only stops budget being wasted on the
/// COMMON case (a row confirmed very recently by something other than
/// this exact lane).
const POSITIVE_REVERIFY_COOLDOWN_SECS: u64 = 86_400;

/// The chain scanner service.
pub struct ChainScanner {
    /// Klever RPC/API configuration.
    config: KleverConfig,
    /// HTTP client for Klever RPC calls.
    http: reqwest::Client,
    /// Persistent storage.
    storage: Storage,
    /// Last processed block height (cursor).
    last_block: u64,
    /// Current exponential backoff duration (reset on success).
    backoff: Duration,
    /// Number of consecutive rate-limit errors.
    consecutive_429s: u32,
    /// Channel to notify the network layer about new channel discoveries.
    /// The network service subscribes to the corresponding GossipSub topic.
    channel_tx: tokio::sync::mpsc::UnboundedSender<u64>,
    /// In-memory cache of resolved `slug → channel_id`. Avoids re-querying the
    /// `getChannelBySlug` SC view (a Klever RPC call) for the same channel
    /// every time a 429-stalled cursor re-scans a block range — the main
    /// source of chain-scan rate-limit amplification. `Mutex` for interior
    /// mutability (resolution runs on `&self`).
    slug_cache: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    /// Timestamp of the last outbound Klever API call, for
    /// `throttle_klever_request`'s self-imposed pacing. `tokio::sync::Mutex`
    /// since the throttle is held across an `.await` (the sleep itself).
    last_klever_request: tokio::sync::Mutex<Option<tokio::time::Instant>>,
    /// Periodic public-channel creator re-verification policy (audit
    /// 2026-09-28) — see `sweep_channel_verification`.
    channel_verify_config: crate::config::ChannelVerifyConfig,
    /// Audit final pre-mainnet W35: shared millis-since-epoch of the last
    /// successful Klever RPC call, read by `MetricsCollector` into
    /// `MetricsSnapshot::klever_rpc_last_success_ms` for the
    /// `KleverDisconnected` alert. Recorded once per successful `poll_blocks`
    /// tick (which always makes at least one real RPC call —
    /// `get_latest_block_height` — even when there's nothing new to
    /// process), not at every individual HTTP call site: a full tick
    /// succeeding is a faithful, single-point connectivity signal, cheaper
    /// than instrumenting every low-level call.
    klever_health: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl ChainScanner {
    /// Create a new chain scanner.
    ///
    /// `channel_tx` notifies the network layer when new channels are discovered
    /// so it can subscribe to the corresponding GossipSub topics.
    pub fn new(
        config: KleverConfig,
        storage: Storage,
        channel_tx: tokio::sync::mpsc::UnboundedSender<u64>,
        klever_health: std::sync::Arc<std::sync::atomic::AtomicU64>,
        channel_verify_config: crate::config::ChannelVerifyConfig,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("creating HTTP client")?;

        let mut last_block = storage.get_chain_cursor()?;

        // If the cursor is 0 (fresh node) and start_block is configured,
        // skip ahead to avoid scanning millions of irrelevant blocks.
        if last_block == 0 && config.start_block > 0 {
            last_block = config.start_block;
            info!(
                start_block = config.start_block,
                contract = %config.contract_address,
                "Chain scanner skipping to start_block (fresh node)"
            );
        } else {
            info!(
                last_block,
                contract = %config.contract_address,
                "Chain scanner initialized"
            );
        }

        Ok(Self {
            config,
            http,
            storage,
            last_block,
            backoff: Duration::ZERO,
            consecutive_429s: 0,
            channel_tx,
            slug_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            last_klever_request: tokio::sync::Mutex::new(None),
            channel_verify_config,
            klever_health,
        })
    }

    /// Run the scanner loop until shutdown.
    pub async fn run(
        &mut self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        if self.config.node_url.is_empty()
            || self.config.api_url.is_empty()
            || self.config.contract_address.is_empty()
        {
            info!("Chain scanner disabled — Klever node_url, api_url, or contract_address not configured");
            let _ = shutdown_rx.recv().await;
            return;
        }

        info!("Chain scanner started, polling every {}ms", self.config.scan_interval_ms);

        let interval_duration = Duration::from_millis(self.config.scan_interval_ms);
        let mut interval = tokio::time::interval(interval_duration);

        // Channel-creator verification sweep (audit 2026-09-28). `None`
        // when disabled, so this arm never wakes the loop at all — mirrors
        // the identical idiom `network/mod.rs` uses for its own disabled
        // periodic-sweep intervals (don't `.max(1)` a zero interval, which
        // would busy-poll forever).
        let mut channel_verify_interval = if self.channel_verify_config.sweep_interval_secs > 0 {
            let mut iv = tokio::time::interval(Duration::from_secs(
                self.channel_verify_config.sweep_interval_secs,
            ));
            iv.tick().await; // skip immediate tick
            Some(iv)
        } else {
            None
        };

        loop {
            tokio::select! {
                _ = async {
                    match channel_verify_interval.as_mut() {
                        Some(iv) => { iv.tick().await; }
                        None => std::future::pending().await,
                    }
                } => {
                    self.sweep_channel_verification(&mut shutdown_rx).await;
                }
                _ = interval.tick() => {
                    // If we're in backoff, wait before trying
                    if !self.backoff.is_zero() {
                        info!(
                            backoff_secs = self.backoff.as_secs(),
                            consecutive_429s = self.consecutive_429s,
                            "Rate-limited, backing off"
                        );
                        tokio::select! {
                            _ = tokio::time::sleep(self.backoff) => {},
                            _ = shutdown_rx.recv() => {
                                info!("Chain scanner shutting down");
                                return;
                            }
                        }
                    }

                    match self.poll_blocks(&mut shutdown_rx).await {
                        Ok(()) => {
                            // Reset backoff on success
                            if self.consecutive_429s > 0 {
                                info!("Chain scanner recovered from rate limiting");
                            }
                            self.backoff = Duration::ZERO;
                            self.consecutive_429s = 0;
                            // W35: a successful tick always makes at least
                            // one real Klever RPC call.
                            let now_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64;
                            self.klever_health.store(now_ms, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("429") || err_str.contains("Too Many Requests") {
                                self.consecutive_429s += 1;
                                let backoff_ms = (BACKOFF_BASE_MS * 2u64.saturating_pow(self.consecutive_429s.saturating_sub(1)))
                                    .min(BACKOFF_MAX_MS);
                                self.backoff = Duration::from_millis(backoff_ms);
                                warn!(
                                    error = %e,
                                    backoff_ms,
                                    consecutive_429s = self.consecutive_429s,
                                    "Chain scanner rate-limited, will back off"
                                );
                            } else {
                                warn!(error = %e, "Chain scanner poll failed");
                            }
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Chain scanner shutting down");
                    break;
                }
            }
        }
    }

    /// Poll for new blocks since the last cursor position.
    async fn poll_blocks(
        &mut self,
        shutdown_rx: &mut tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        let latest = self.get_latest_block_height().await?;

        // Store chain tip for dashboard sync lag calculation (spec 10-dashboard.md §6)
        let _ = self.storage.put_cf(
            cf::NODE_STATE,
            crate::storage::schema::state_keys::CHAIN_TIP,
            &latest.to_be_bytes(),
        );

        if latest <= self.last_block {
            return Ok(());
        }

        let behind = latest - self.last_block;
        let catching_up = behind > CATCHUP_THRESHOLD;
        let batch_size = if catching_up { CATCHUP_BATCH_SIZE } else { TIP_BATCH_SIZE };

        if catching_up {
            info!(
                behind,
                from = self.last_block + 1,
                to = latest,
                batch_size,
                "Catch-up scan starting"
            );
        } else {
            debug!(
                from = self.last_block + 1,
                to = latest,
                "Scanning blocks"
            );
        }

        let mut current = self.last_block + 1;

        while current <= latest {
            let end = (current + batch_size - 1).min(latest);

            self.process_block_range(current, end).await?;

            // Update cursor after successful batch
            self.last_block = end;
            self.storage.set_chain_cursor(end)?;
            // Snapshot-bootstrap GC: if a recent snapshot apply left a
            // rollback checkpoint on disk and we've now scanned far enough
            // past the cutoff to consider it safely committed, delete it.
            // Spec 11-snapshot-sync.md §5a.6.
            gc_snapshot_rollback_if_ready(&self.storage, self.last_block);
            current = end + 1;

            // Inter-batch delay to avoid hitting rate limits
            if current <= latest {
                let delay = if catching_up {
                    Duration::from_millis(CATCHUP_BATCH_DELAY_MS)
                } else {
                    Duration::from_millis(200)
                };

                // Check for shutdown during the delay
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {},
                    _ = shutdown_rx.recv() => {
                        info!(
                            cursor = self.last_block,
                            "Chain scanner shutting down mid-scan"
                        );
                        return Ok(());
                    }
                }
            }
        }

        if catching_up {
            info!(cursor = self.last_block, "Catch-up scan complete");
        }

        Ok(())
    }

    /// Self-imposed pacing before every outbound Klever API call — see
    /// `KLEVER_REQUEST_MIN_SPACING_MS`. Proactive, unlike the reactive
    /// exponential backoff in `run`'s error handler: this avoids drawing a
    /// 429 in the first place instead of paying for one and backing off
    /// after the fact.
    async fn throttle_klever_request(&self) {
        let mut last = self.last_klever_request.lock().await;
        if let Some(prev) = *last {
            let min_next = prev + Duration::from_millis(KLEVER_REQUEST_MIN_SPACING_MS);
            let now = tokio::time::Instant::now();
            if min_next > now {
                tokio::time::sleep(min_next - now).await;
            }
        }
        *last = Some(tokio::time::Instant::now());
    }

    /// Get the latest block height from the Klever API.
    ///
    /// Uses the API block list endpoint (not the node status endpoint)
    /// to avoid aggressive rate limiting on node.testnet.klever.org.
    async fn get_latest_block_height(&self) -> Result<u64> {
        let url = format!("{}/v1.0/block/list?limit=1", self.config.api_url);

        self.throttle_klever_request().await;
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .context("fetching block list")?;

        let status = response.status();
        let text = response.text().await.context("reading block list body")?;

        if !status.is_success() {
            anyhow::bail!(
                "block list HTTP {}: {}",
                status,
                crate::util::truncate_str(&text, 200) // audit 2026-06-07 (W16)
            );
        }

        let resp: serde_json::Value =
            serde_json::from_str(&text).context("parsing block list JSON")?;

        let height = resp
            .pointer("/data/blocks/0/nonce")
            .and_then(|v| v.as_u64())
            .context("extracting block height from API")?;

        Ok(height)
    }

    /// Process a range of blocks — fetch transactions and filter for Ogmara SC events.
    ///
    /// Paginates through the transaction list to ensure all transactions are captured
    /// even in busy block ranges. Capped at 50 pages to prevent infinite loops.
    async fn process_block_range(&self, start: u64, end: u64) -> Result<()> {
        // W17 (audit 2026-06-07): a range with more SC txs than the page cap
        // used to `break` and let the caller advance the cursor PAST it →
        // permanent silent event loss. Instead, subdivide an over-capped range
        // (work stack) so every block is fully covered before the cursor moves.
        let mut stack = vec![(start, end)];
        while let Some((s, e)) = stack.pop() {
            match self.process_range_paged(s, e).await? {
                PageOutcome::Complete => {}
                PageOutcome::CapExceededDense => {
                    if s >= e {
                        // A single block exceeding the cap is pathological (one block
                        // with >MAX_PAGES*100 SC txs to our contract) — can't split
                        // further; warn rather than loop forever.
                        warn!(block = s, "single block exceeds pagination cap — some SC txs may be missed");
                    } else {
                        let mid = s + (e - s) / 2;
                        // Push high half first so the low half is processed first.
                        stack.push((mid + 1, e));
                        stack.push((s, mid));
                    }
                }
                PageOutcome::CapExceededTooDeep => {
                    // Subdividing would not help — see `PageOutcome` doc comment.
                    // Every sub-range would independently re-walk the same
                    // newest-first pages and hit the same cap, multiplying
                    // wasted API calls (and rate-limit exposure) for zero
                    // additional coverage.
                    //
                    // SECURITY (audit 2026-09-28): this is a PERMANENT gap, not
                    // a deferred one. The cursor still advances past `end` once
                    // `process_block_range` returns (`poll_blocks`'s
                    // `set_chain_cursor`), and nothing else in this codebase
                    // ever revisits an already-passed range — there is no gap
                    // queue, no rewind, and Phase 2 snapshot bootstrap only
                    // triggers on a strictly-fresh node (`cursor == 0` at
                    // startup, `node.rs`), never mid-run. This is a real,
                    // pre-existing gap (the old subdivision-to-single-block
                    // path was equally unable to reach a genuinely-too-deep
                    // range — see PageOutcome doc comment) that this change
                    // makes far cheaper to reach, not one it introduces.
                    //
                    // FIXED (audit 2026-09-29): a `ChannelCreated` lost here
                    // no longer leaves a squatted `channel_id`'s L2-unverified
                    // creator claim (`messages::router`) standing permanently
                    // — `sweep_channel_verification` independently re-confirms
                    // any unverified public/read-public channel's creator via
                    // the SC's live `getChannelCreator` view, which doesn't
                    // depend on this historical scan ever reaching the event.
                    // What's still true: any OTHER SC event type lost to a gap
                    // (user registrations, delegations, non-channel state) has
                    // no equivalent independent-reverify path yet, and this
                    // range itself is still never retried — recorded below so
                    // it's operator-visible instead of silently invisible.
                    warn!(
                        start = s,
                        end = e,
                        "range too far behind chain tip to reach within the pagination \
                         budget — skipping without subdividing (see process_range_paged); \
                         SC events in this range are PERMANENTLY missed on this node, not \
                         deferred — nothing currently retries a skipped range"
                    );
                    self.record_chain_scan_gap(s, e);
                }
            }
        }
        Ok(())
    }

    /// Increment the monotonic lifetime channel-verification-alerts
    /// counter (audit 2026-09-29, security-review finding: the fabricated-
    /// public-claim and poisoning signals were `warn!`-log-only, unlike
    /// the chain-scan-gap counter added in the same pass). Best-effort —
    /// a failure here only loses a diagnostic count, never correctness.
    fn bump_channel_verification_alerts(&self) {
        let current = read_u64_node_state(
            &self.storage,
            crate::storage::schema::state_keys::CHANNEL_VERIFICATION_ALERTS_TOTAL,
        );
        if let Err(e) = self.storage.put_cf(
            cf::NODE_STATE,
            crate::storage::schema::state_keys::CHANNEL_VERIFICATION_ALERTS_TOTAL,
            &current.saturating_add(1).to_be_bytes(),
        ) {
            warn!(error = %e, "bump_channel_verification_alerts: write failed");
        }
    }

    /// Append a newly-discovered permanent chain-scan gap to the persisted
    /// list (`read_chain_scan_gaps`/`GapRecord`), capped at
    /// `MAX_CHAIN_SCAN_GAPS` (oldest dropped first). Best-effort — a failure
    /// here only loses diagnostic visibility, never correctness, so it's
    /// logged and swallowed rather than propagated.
    fn record_chain_scan_gap(&self, start: u64, end: u64) {
        let mut gaps = read_chain_scan_gaps(&self.storage);
        // Dedup: a mid-batch error can cause `process_block_range` to
        // discard progress and the SAME range to be reprocessed (and
        // re-recorded) on a later tick — skip an exact repeat of the
        // immediately preceding record rather than inflating the count.
        if gaps.last().map(|g| (g.start, g.end)) == Some((start, end)) {
            return;
        }
        let recorded_at = now_unix_secs();
        gaps.push(GapRecord {
            start,
            end,
            recorded_at,
        });
        cap_gap_list(&mut gaps, MAX_CHAIN_SCAN_GAPS);
        // Separate MONOTONIC lifetime counter, alongside the capped list —
        // the list's own derived total can DECREASE as the node gets
        // worse (oldest records dropped past MAX_CHAIN_SCAN_GAPS), which
        // would be exactly the kind of silently-reassuring metric this
        // whole feature exists to eliminate. Only bumped here, in lockstep
        // with a genuine (deduped) new gap record.
        let width = end.saturating_sub(start).saturating_add(1);
        let total_so_far = read_u64_node_state(
            &self.storage,
            crate::storage::schema::state_keys::CHAIN_SCAN_GAP_BLOCKS_TOTAL,
        );
        if let Err(e) = self.storage.put_cf(
            cf::NODE_STATE,
            crate::storage::schema::state_keys::CHAIN_SCAN_GAP_BLOCKS_TOTAL,
            &total_so_far.saturating_add(width).to_be_bytes(),
        ) {
            warn!(error = %e, "record_chain_scan_gap: monotonic total write failed");
        }
        match serde_json::to_vec(&gaps) {
            Ok(bytes) => {
                if let Err(e) = self.storage.put_cf(
                    cf::NODE_STATE,
                    crate::storage::schema::state_keys::CHAIN_SCAN_GAPS,
                    &bytes,
                ) {
                    warn!(error = %e, "record_chain_scan_gap: write failed");
                }
            }
            Err(e) => warn!(error = %e, "record_chain_scan_gap: serialization failed"),
        }
    }

    /// Page through type-63 SC transactions for `[start, end]`.
    ///
    /// Returns `PageOutcome::Complete` when the range was fully processed (a
    /// short page terminated it), or one of the two cap-exceeded variants
    /// (audit 2026-06-07 W17, refined — see `PageOutcome` doc comment) when
    /// it hit the page cap: `CapExceededDense` if the caller should
    /// subdivide, `CapExceededTooDeep` if subdividing would not help.
    ///
    /// **The Klever testnet API's `startBlock`/`endBlock` query params are
    /// silently NOT honored** — confirmed directly: a query with
    /// `startBlock=1000000&endBlock=1000100` against a chain at height
    /// ~12.7M still returned the current-tip transactions. The endpoint
    /// just returns the most recent matching transactions, newest-first,
    /// regardless of the requested range. Every prior version of this
    /// function trusted the server to filter and only used `tx_count < 100`
    /// to detect "range exhausted" — which a consistently-active contract
    /// never satisfies, so every tick re-walked and re-wrote the same
    /// recent window of events forever (root cause of l2-node 0.130.1/
    /// 0.130.2's WAL write amplification investigation — those two fixes
    /// shrunk the batch size but couldn't fix this, since the bug is
    /// independent of what range is requested). Filtering is now done
    /// client-side against `tx.block_num`, with early pagination
    /// termination once results walk past `start` (safe given the
    /// newest-first ordering — every subsequent page can only be older
    /// still, so there is nothing further to find in-range).
    async fn process_range_paged(&self, start: u64, end: u64) -> Result<PageOutcome> {
        let mut page = 1u64;
        const MAX_PAGES: u64 = 50;
        // Set once a transaction older than `start` is seen — newest-first
        // ordering means every remaining/later-page entry is older still,
        // so there is nothing left to find in-range and paging can stop.
        let mut walked_past_start = false;
        // Page at which paging FIRST reached the neighborhood of `end` (an
        // in-range or too-old transaction). `None` means every page so far
        // was still newer than `end`.
        //
        // Audit 2026-09-28 (code review, boundary-misclassification finding):
        // a bare "did we ever reach it" bool is not enough — a range whose
        // first in-range transaction lands on, say, page 48 has essentially
        // no real budget left, but a bool would still classify it as
        // `CapExceededDense` and subdivide. Subdividing does NOT help there:
        // the upper half shares the identical `end`, so it re-walks the
        // exact same ~48 TooNew pages and hits the exact same wall; the
        // lower half's target is only deeper still. That reproduces the
        // very ~400-call explosion this fix exists to remove, just for a
        // narrower set of ranges (those whose `end` sits within roughly the
        // last ~2,500-5,000 matching transactions behind tip). Tracking the
        // page number lets the cap-check below require that MEANINGFUL
        // budget remained, not just that the range was technically reached.
        let mut first_in_range_page: Option<u64> = None;

        loop {
            if page > MAX_PAGES {
                return Ok(classify_cap_outcome(first_in_range_page, MAX_PAGES));
            }
            let url = format!(
                "{}/v1.0/transaction/list?status=success&type=63&toAddress={}&page={}&limit=100&startBlock={}&endBlock={}",
                self.config.api_url, self.config.contract_address, page, start, end
            );

            self.throttle_klever_request().await;
            let response = self
                .http
                .get(&url)
                .send()
                .await
                .context("fetching block transactions")?;

            let status = response.status();
            let text = response.text().await.context("reading transactions body")?;

            if !status.is_success() {
                anyhow::bail!(
                    "transaction list HTTP {}: {}",
                    status,
                    crate::util::truncate_str(&text, 200) // audit 2026-06-07 (W16)
                );
            }

            let resp: serde_json::Value =
                serde_json::from_str(&text).context("parsing block transactions JSON")?;

            // Extract transactions array
            let txs = match resp.pointer("/data/transactions") {
                Some(serde_json::Value::Array(arr)) if !arr.is_empty() => arr,
                _ => return Ok(PageOutcome::Complete), // No (more) transactions — range complete
            };

            let tx_count = txs.len();

            for tx_value in txs {
                let tx: KleverTransaction = match serde_json::from_value(tx_value.clone()) {
                    Ok(tx) => tx,
                    Err(e) => {
                        debug!(error = %e, "Skipping unparseable transaction");
                        continue;
                    }
                };

                if tx.status != "success" {
                    continue;
                }

                // The API does NOT actually filter by startBlock/endBlock (see
                // the function doc comment) — enforce the intended range
                // ourselves.
                match classify_block_range_position(tx.block_num, start, end) {
                    RangePosition::TooNew => continue,
                    RangePosition::TooOld => {
                        walked_past_start = true;
                        // Provably inert today (code audit 2026-09-28):
                        // `walked_past_start` forces `Complete` at the end of
                        // THIS page, before the cap-check can ever read
                        // `first_in_range_page` again. Set anyway — it is
                        // the semantically correct value (we did reach the
                        // target range) and is one refactor away from
                        // mattering if that early return ever changes.
                        first_in_range_page.get_or_insert(page);
                        continue;
                    }
                    RangePosition::InRange => {
                        first_in_range_page.get_or_insert(page);
                    }
                }

                // Already filtered by toAddress in the API query, but double-check
                // the contract call parameter address matches
                let contract_address = tx
                    .contract
                    .first()
                    .map(|c| c.parameter.address.as_str())
                    .unwrap_or("");

                if contract_address != self.config.contract_address {
                    continue;
                }

                // Decode the SC function call from the data field
                // data[0] is hex-encoded "functionName@arg1@arg2"
                let call_data = match tx.data.first() {
                    Some(hex_data) => {
                        match hex::decode(hex_data) {
                            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                            Err(_) => continue,
                        }
                    }
                    None => continue,
                };

                if let Some(event) = parser::parse_sc_call(&call_data, &tx.sender, tx.timestamp) {
                    if let Err(e) = self.handle_event(event).await {
                        warn!(
                            block = start,
                            tx = %tx.hash,
                            error = %e,
                            "Failed to handle SC event"
                        );
                    }
                }
            }

            // Fewer than a full page → no more transactions at all (the
            // one server-side signal that IS reliable). Or: this page
            // already walked past `start` — every further page can only
            // be older still, so there is nothing left to find in-range.
            if tx_count < 100 || walked_past_start {
                return Ok(PageOutcome::Complete);
            }
            page += 1;

            // Brief pause between pages
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Handle a parsed SC event — update local state in RocksDB.
    async fn handle_event(&self, event: ScEvent) -> Result<()> {
        match event {
            ScEvent::UserRegistered {
                address,
                public_key,
                timestamp,
            } => {
                // Merge with existing record to preserve profile data.
                // The chain scanner may re-process blocks, so this must be idempotent.
                //
                // Merge FIELD-WISE into the raw JSON, never through the typed
                // `UserRecord`. The `users` row is a free-form JSON document owned
                // jointly by this scanner and the message router
                // (`messages/router.rs`, ProfileUpdate arm), and `UserRecord` is a
                // CLOSED struct listing only six keys — round-tripping through it
                // silently deletes every key it does not declare. That previously
                // dropped `profile_updated_at`, which is the P-2 anti-replay
                // watermark: with it gone, `prev_profile_ts` reads back as 0 and a
                // stale ProfileUpdate served over identity-sync (which skips the
                // clock-drift check) applies cleanly — exactly the backfill
                // downgrade the watermark exists to prevent. It now also carries a
                // wallet's bot descriptor (spec 01 §3.11).
                //
                // Do NOT "fix" this by adding fields to `UserRecord`; that repairs
                // today and breaks again the next time the router learns a key.
                if let Some(existing) = self.storage.get_cf(cf::USERS, address.as_bytes())? {
                    let record = merge_user_fields(
                        &existing,
                        &address,
                        &[
                            ("public_key", serde_json::json!(public_key)),
                            ("registered_at", serde_json::json!(timestamp)),
                        ],
                    );
                    let bytes = serde_json::to_vec(&record)?;
                    self.storage
                        .put_cf(cf::USERS, address.as_bytes(), &bytes)?;
                    info!(address = %address, "User registration updated (on-chain, preserved profile)");
                } else {
                    // New user — create fresh record
                    let record = UserRecord {
                        address: address.clone(),
                        public_key,
                        registered_at: timestamp,
                        display_name: None,
                        avatar_cid: None,
                        bio: None,
                        // Sentinel, not a real timestamp — see the field's
                        // doc comment (`UserRecord::profile_updated_at`,
                        // security-audit finding HIGH-2). Marks "settled:
                        // no ProfileUpdate has ever been sent" so this
                        // wallet isn't re-triggered by the identity-resync
                        // sweep forever.
                        profile_updated_at: Some(0),
                    };
                    let bytes = serde_json::to_vec(&record)?;
                    self.storage
                        .put_cf(cf::USERS, address.as_bytes(), &bytes)?;
                    self.storage.increment_stat(
                        crate::storage::schema::state_keys::TOTAL_USERS,
                    )?;
                    info!(address = %address, "User registered (on-chain)");
                }
            }

            ScEvent::PublicKeyUpdated {
                address,
                public_key,
            } => {
                if let Some(existing) = self.storage.get_cf(cf::USERS, address.as_bytes())? {
                    // Same helper as the UserRegistered arm — see its doc comment
                    // for why this must not go through `UserRecord`.
                    let record = merge_user_fields(
                        &existing,
                        &address,
                        &[("public_key", serde_json::json!(public_key))],
                    );
                    let bytes = serde_json::to_vec(&record)?;
                    self.storage
                        .put_cf(cf::USERS, address.as_bytes(), &bytes)?;
                    info!(address = %address, "Public key updated (on-chain)");
                } else {
                    warn!(address = %address, "PublicKeyUpdated for unknown user — may have missed registration event");
                }
            }

            ScEvent::ChannelCreated {
                channel_id: _,
                creator,
                slug,
                channel_type,
                timestamp,
            } => {
                // Resolve the actual channel_id from the SC via getChannelBySlug view query
                let channel_id = match self.query_channel_id_by_slug(&slug).await {
                    Ok(id) => id,
                    Err(e) => {
                        warn!(slug = %slug, error = %e, "Failed to resolve channel_id — skipping");
                        return Ok(());
                    }
                };

                let channel_key = channel_id.to_be_bytes();

                // Skip channels that were intentionally deleted (tombstone check)
                if self.storage.exists_cf(cf::DELETED_CHANNELS, &channel_key)? {
                    tracing::trace!(channel_id, "Skipping deleted channel (tombstone exists)");
                    return Ok(());
                }

                // Only increment counter for genuinely new channels (idempotent on re-scan)
                let is_new = !self.storage.exists_cf(cf::CHANNELS, &channel_key)?;

                // If a record already exists (from prior on-chain re-scan or L2
                // ChannelUpdate envelope), JSON-merge: overwrite only the
                // on-chain authoritative fields and preserve every L2-only
                // field (display_name, description, member_count, logo_cid,
                // banner_cid, website_url, tags, and anything added later).
                // This avoids dropping L2 metadata on re-scan, which previously
                // erased channel avatars/banners on public channels every time
                // the scanner re-processed their ChannelCreated event.
                // Round 7 (security audit finding): tracks whether the
                // merge below detected-but-deliberately-left-uncorrected
                // a Private/on-chain collision, so the `mark_channel_
                // creator_verified` call further down can be skipped for
                // it — stamping "verified" on a row that was NOT
                // actually corrected would arm the 24h positive-reverify
                // cooldown on exactly the row that most needs to keep
                // being re-checked and re-alerted on every future pass.
                let mut merge_was_private_collision = false;
                let bytes = if let Ok(Some(existing)) = self.storage.get_cf(cf::CHANNELS, &channel_key) {
                    let mut meta = serde_json::from_slice::<serde_json::Value>(&existing)
                        .unwrap_or_else(|e| {
                            tracing::error!(
                                channel_id,
                                error = %e,
                                "CHANNELS record failed to parse as JSON — rebuilding from on-chain fields"
                            );
                            serde_json::json!({})
                        });
                    // Round-6 audit finding (NOTE7), extended in round 7:
                    // `channel_type` is L2-authoritative for the
                    // Public<->ReadPublic distinction (`messages::
                    // router`'s `ChannelUpdate`) and meant to diverge
                    // from the immutable on-chain snapshot — the exact
                    // invariant `apply_channel_verification_result`'s
                    // `Confirmed` outcome already protects elsewhere in
                    // this same pass (round 2's rejected design
                    // overwrote it unconditionally). Round 6 fixed
                    // `channel_type` here but round 7's own re-audit
                    // found `creator`/`slug`/`created_at` in this SAME
                    // branch were STILL unconditional — a legacy
                    // pre-`PRIVATE_CHANNEL_ID_FLOOR` Private row whose id
                    // collides with a real on-chain channel had its
                    // ownership and identity silently overwritten every
                    // re-scan. The actual merge decision is pulled into
                    // `merge_channel_created_into_existing` (pure, unit-
                    // tested) since this whole match arm has no HTTP-
                    // mocking test harness otherwise.
                    match merge_channel_created_into_existing(
                        &mut meta,
                        channel_id,
                        &slug,
                        &creator,
                        timestamp,
                    ) {
                        ChannelFieldMergeOutcome::PrivateCollisionDetected => {
                            tracing::warn!(
                                channel_id,
                                "on-chain ChannelCreated event landed on a currently-Private \
                                 local row — possible pre-floor legacy self-label collision; \
                                 row left untouched, needs operator review"
                            );
                            self.bump_channel_verification_alerts();
                            merge_was_private_collision = true;
                            serde_json::to_vec(&meta)?
                        }
                        ChannelFieldMergeOutcome::Merged => serde_json::to_vec(&meta)?,
                        ChannelFieldMergeOutcome::NotAnObject => {
                            // Existing record is JSON but not an object — skip
                            // the merge (don't abort the whole batch) and keep
                            // going.
                            tracing::warn!(
                                channel_id,
                                "CHANNELS record is not a JSON object — skipping merge"
                            );
                            return Ok(());
                        }
                    }
                } else {
                    // First time we've seen this channel — write the canonical
                    // ChannelRecord with no L2 fields populated yet.
                    let record = ChannelRecord {
                        channel_id,
                        slug: slug.clone(),
                        creator: creator.clone(),
                        channel_type,
                        created_at: timestamp,
                        display_name: None,
                        description: None,
                        member_count: 0,
                    };
                    serde_json::to_vec(&record)?
                };
                if is_new {
                    // Code Audit WARNING #2 fix: the row write and the pending
                    // member-removal-claim replay must be ONE
                    // `channel_membership_lock`-guarded critical section — see
                    // `put_channel_and_replay_pending_member_removals`'s doc
                    // comment for the orphaned-claim race this closes.
                    self.storage
                        .put_channel_and_replay_pending_member_removals(channel_id, &bytes)?;
                    // Chain-derived — the creator IS the on-chain value.
                    // Recorded in the separate CHANNEL_VERIFICATION CF, not
                    // as a field on this row (see that CF's doc comment).
                    // Stamped AFTER the row above is durably persisted
                    // (round-6 audit finding NOTE4): stamping first would
                    // leave a "verified" record standing even if the
                    // write just above failed, protecting a row that was
                    // never actually corrected from the sweep's own
                    // re-check via the new 24h positive-reverify cooldown.
                    if let Err(e) = self
                        .storage
                        .mark_channel_creator_verified(channel_id, now_unix_secs())
                    {
                        tracing::warn!(channel_id, error = %e, "failed to record channel verification state");
                    }

                    self.storage.increment_stat(
                        crate::storage::schema::state_keys::TOTAL_CHANNELS,
                    )?;

                    // Add creator as first member with "creator" role
                    let member_key = crate::storage::schema::encode_channel_member_key(
                        channel_id, &creator,
                    );
                    let member_record = serde_json::json!({
                        "joined_at": timestamp,
                        "role": "creator",
                    });
                    if let Ok(member_bytes) = serde_json::to_vec(&member_record) {
                        let _ = self.storage.put_cf(cf::CHANNEL_MEMBERS, &member_key, &member_bytes);
                    }

                    // W14: this on-chain scan is the first time this channel_id's
                    // creator has become known on this node — consume any pending
                    // delete claim recorded (via a `ChannelDelete` envelope) while the
                    // channel was still unknown here. Mirrors the identical check in
                    // `messages::router::update_indexes`'s `ChannelCreate` handler,
                    // which covers the other possible "creator becomes known first"
                    // path (an L2 envelope beating the chain scanner to it).
                    if let Ok(claim) = self.storage.take_pending_channel_delete(channel_id) {
                        if crate::messages::router::channel_delete_claim_matches(
                            claim.as_ref(),
                            &creator,
                        ) {
                            self.storage.tombstone_channel(channel_id, timestamp, None)?;
                        }
                    }

                    // Notify network layer to subscribe to this channel's GossipSub
                    // topic — only for a genuinely NEW channel. A `ChannelCreated`
                    // event for an already-known channel can keep re-parsing on
                    // repeated scans (e.g. a slow/rate-limited catch-up re-fetching
                    // an overlapping block range); resending on every re-parse fired
                    // a redundant subscribe + backfill-reconciliation-fanout + log
                    // line for the SAME channel over and over, observed as a tight,
                    // continuously-repeating cycle in production (freeweb) — pure
                    // system load for a topic the node is already subscribed to
                    // (`subscribe_channel` is idempotent, but idempotent isn't free:
                    // it still triggers `maybe_trigger_backfill`'s peer fanout).
                    let _ = self.channel_tx.send(channel_id);
                    info!(channel_id, slug = %slug, "Channel created (on-chain)");
                } else {
                    self.storage
                        .put_cf(cf::CHANNELS, &channel_key, &bytes)?;
                    // Chain-derived — corrects any prior L2-unverified
                    // skeleton's creator. Recorded in the separate
                    // CHANNEL_VERIFICATION CF, never as a field on this
                    // row (see that CF's doc comment — anchor
                    // state-root divergence, audit 2026-09-29). Stamped
                    // AFTER the row above is durably persisted (round-6
                    // audit finding NOTE4 — see the sibling `is_new`
                    // branch's comment for the full reasoning). Skipped
                    // entirely when the merge detected-but-didn't-
                    // correct a Private collision (round 7) — see
                    // `merge_was_private_collision`'s doc comment above.
                    if !merge_was_private_collision {
                        if let Err(e) = self
                            .storage
                            .mark_channel_creator_verified(channel_id, now_unix_secs())
                        {
                            tracing::warn!(channel_id, error = %e, "failed to record channel verification state");
                        }
                    }
                }
            }

            ScEvent::ChannelTransferred {
                channel_id,
                from: _,
                to,
            } => {
                if let Some(existing) =
                    self.storage
                        .get_cf(cf::CHANNELS, &channel_id.to_be_bytes())?
                {
                    // JSON-merge to preserve L2-only fields (logo_cid, banner_cid,
                    // website_url, tags). Same rationale as ChannelCreated above:
                    // struct round-trip would silently drop them.
                    let mut meta = serde_json::from_slice::<serde_json::Value>(&existing)
                        .unwrap_or_else(|e| {
                            tracing::error!(
                                channel_id,
                                error = %e,
                                "CHANNELS record corrupted on transfer — rebuilding from on-chain fields"
                            );
                            serde_json::json!({})
                        });
                    match apply_channel_transfer_to_existing(&mut meta, &to) {
                        ChannelFieldMergeOutcome::PrivateCollisionDetected => {
                            tracing::warn!(
                                channel_id,
                                "on-chain ChannelTransferred event landed on a currently-Private \
                                 local row — possible pre-floor legacy self-label collision; \
                                 row left untouched, needs operator review"
                            );
                            self.bump_channel_verification_alerts();
                        }
                        ChannelFieldMergeOutcome::Merged => {
                            let bytes = serde_json::to_vec(&meta)?;
                            self.storage
                                .put_cf(cf::CHANNELS, &channel_id.to_be_bytes(), &bytes)?;
                            // Chain-derived, same as ChannelCreated's merge —
                            // this IS a fresh on-chain confirmation of the new
                            // creator, not a reason to leave a stale
                            // verification state standing (audit 2026-09-29: a
                            // never-re-checked verification flag was the
                            // mechanism by which a transfer landing in a scan
                            // gap reproduced this whole bug class invisibly).
                            // Recorded in the separate CHANNEL_VERIFICATION CF.
                            if let Err(e) = self
                                .storage
                                .mark_channel_creator_verified(channel_id, now_unix_secs())
                            {
                                tracing::warn!(channel_id, error = %e, "failed to record channel verification state");
                            }
                            info!(channel_id, "Channel transferred (on-chain)");
                        }
                        ChannelFieldMergeOutcome::NotAnObject => {
                            tracing::warn!(
                                channel_id,
                                "CHANNELS record is not a JSON object — skipping transfer write"
                            );
                        }
                    }
                }
            }

            ScEvent::DeviceDelegated {
                user,
                device_key,
                permissions,
                expires_at,
                timestamp,
            } => {
                let record = DelegationRecord {
                    user_address: user.clone(),
                    device_pub_key: device_key.clone(),
                    permissions,
                    expires_at,
                    created_at: timestamp,
                    active: true,
                };
                let key = crate::storage::schema::encode_delegation_key(&user, &device_key);
                let bytes = serde_json::to_vec(&record)?;
                self.storage.put_cf(cf::DELEGATIONS, &key, &bytes)?;

                // Also write DEVICE_WALLET_MAP so identity resolution works.
                // Convert hex pubkey → ogd1 device address for the map key.
                if let Ok(pubkey_bytes) = hex::decode(&device_key) {
                    if pubkey_bytes.len() == 32 {
                        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(
                            &<[u8; 32]>::try_from(pubkey_bytes.as_slice()).unwrap(),
                        ) {
                            if let Ok(device_address) = crate::crypto::device_pubkey_to_address(&vk) {
                                let _ = self.storage.put_cf(
                                    cf::DEVICE_WALLET_MAP,
                                    device_address.as_bytes(),
                                    user.as_bytes(),
                                );
                                // Also write reverse mapping
                                let wd_key = crate::storage::schema::encode_wallet_device_key(
                                    &user, &device_address,
                                );
                                let claim = serde_json::json!({
                                    "device_address": device_address,
                                    "wallet_address": user,
                                    "created_at": timestamp,
                                });
                                if let Ok(claim_bytes) = serde_json::to_vec(&claim) {
                                    let _ = self.storage.put_cf(
                                        cf::WALLET_DEVICES, &wd_key, &claim_bytes,
                                    );
                                }
                            }
                        }
                    }
                }

                info!(user = %user, "Device delegated (on-chain)");
            }

            ScEvent::DeviceRevoked {
                user,
                device_key,
                timestamp: _,
            } => {
                let key = crate::storage::schema::encode_delegation_key(&user, &device_key);
                if let Some(existing) = self.storage.get_cf(cf::DELEGATIONS, &key)? {
                    let mut record: DelegationRecord = serde_json::from_slice(&existing)?;
                    record.active = false;
                    let bytes = serde_json::to_vec(&record)?;
                    self.storage.put_cf(cf::DELEGATIONS, &key, &bytes)?;
                    info!(user = %user, "Device revoked (on-chain)");
                }
            }

            ScEvent::StateAnchored {
                block_height,
                state_root,
                message_count,
                channel_count,
                user_count,
                node_id,
                anchorer,
                timestamp,
            } => {
                let record = StateAnchorRecord {
                    block_height,
                    state_root,
                    message_count,
                    channel_count,
                    user_count,
                    node_id,
                    anchorer,
                    anchored_at: timestamp,
                };
                let bytes = serde_json::to_vec(&record)?;
                self.storage
                    .put_cf(cf::STATE_ANCHORS, &block_height.to_be_bytes(), &bytes)?;

                // Write anchor-by-node reverse index for verification badges
                let anchor_node_key = crate::storage::schema::encode_anchor_by_node_key(
                    &record.node_id,
                    record.anchored_at,
                );
                self.storage.put_cf(
                    cf::ANCHOR_BY_NODE,
                    &anchor_node_key,
                    &block_height.to_be_bytes(),
                )?;

                debug!(block_height, "State anchor recorded");
            }

            ScEvent::TipSent {
                sender, recipient, amount, ..
            } => {
                debug!(
                    sender = %sender,
                    recipient = %recipient,
                    amount,
                    "Tip sent (on-chain)"
                );
                // Tip notifications are handled by the notification engine
            }
        }

        Ok(())
    }

    /// Query the SC for a channel's ID by its slug via the VM hex endpoint.
    async fn query_channel_id_by_slug(&self, slug: &str) -> Result<u64> {
        // Cache hit → skip the SC view query entirely. A channel_id is
        // immutable once assigned, so a cached resolution is always valid; this
        // is what stops a re-scanned block range from re-hammering Klever's RPC.
        if let Ok(cache) = self.slug_cache.lock() {
            if let Some(&id) = cache.get(slug) {
                return Ok(id);
            }
        }

        let slug_hex = hex::encode(slug);
        let url = format!("{}/vm/hex", self.config.node_url);

        let body = serde_json::json!({
            "scAddress": self.config.contract_address,
            "funcName": "getChannelBySlug",
            "args": [slug_hex]
        });

        self.throttle_klever_request().await;
        let resp: serde_json::Value = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("querying getChannelBySlug")?
            .json()
            .await
            .context("parsing getChannelBySlug response")?;

        let hex_data = resp
            .pointer("/data/data")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if hex_data.is_empty() {
            anyhow::bail!("getChannelBySlug returned empty for slug '{}'", slug);
        }

        // Decode variable-length big-endian u64
        let bytes = hex::decode(hex_data)
            .context("decoding channel ID hex")?;
        if bytes.len() > 8 {
            anyhow::bail!("channel ID too large: {} bytes", bytes.len());
        }
        let mut padded = [0u8; 8];
        padded[8 - bytes.len()..].copy_from_slice(&bytes);
        let channel_id = u64::from_be_bytes(padded);

        // Cache the resolution so future re-scans of this range don't re-query.
        // Bounded (audit 2026-06-07 W18): slugs come from on-chain channel
        // creates (permissionless), so an unbounded map is a slow memory-growth
        // vector. channel_id is immutable, so clearing on overflow is safe — the
        // worst case is a few re-queries after a flush.
        if let Ok(mut cache) = self.slug_cache.lock() {
            const SLUG_CACHE_CAP: usize = 10_000;
            if cache.len() >= SLUG_CACHE_CAP {
                cache.clear();
            }
            cache.insert(slug.to_string(), channel_id);
        }
        Ok(channel_id)
    }

    /// Periodic re-verification of channel `creator` claims against the
    /// SC's live registry (audit 2026-09-29, v2 redesign). Walks the SC's
    /// OWN authoritative id space directly (`1..=channel_count`, via
    /// `sc_views::get_stats`) instead of scanning the local `CHANNELS`
    /// table — this is the key structural fix over the first attempt:
    /// since channel_ids are minted strictly sequentially on-chain and
    /// never reused (confirmed against `smart-contract/src/channels.rs`),
    /// this enumeration space is complete and entirely independent of
    /// whatever an attacker manages to inject into the LOCAL table. A
    /// local-table-scan design is trivially starvable (flood the local
    /// table with cheap junk unverified rows, and they compete 1:1 for the
    /// same fixed per-tick budget as legitimate channels); this one is
    /// not, because junk that was never really minted on-chain simply
    /// never enters the id range being walked.
    ///
    /// Three lanes, each with its OWN reserved share of the per-tick
    /// SC-call budget (`max_retriggers_per_sweep`, via
    /// `partition_sweep_budget`) — a single shared budget drained by lane
    /// in priority order let an earlier lane permanently starve a later
    /// one (rounds 4 and 5 each found a real instance of this). A
    /// fourth lane ("pending recheck", an out-of-band queue for a
    /// late-arriving local create) existed in rounds 3.1-4 and was
    /// removed in round 5 after two successive designs for it (a
    /// global-cursor rewind, then the queue itself) each turned out to
    /// be their own attacker-exploitable resource — see
    /// `messages::router`'s `ChannelCreate` handler for the removal
    /// rationale. That specific timing window now falls back to Lane 3's
    /// own cadence, same as every other "detection, not instant closure"
    /// residual this feature already carries.
    /// - **Lane 1 (priority)**: every id newer than
    ///   `CHANNEL_VERIFY_HIGH_WATER`. This is what actually closes the
    ///   squatting window fast — should almost always be 0-1 ids per tick,
    ///   since legitimate channel creation is infrequent.
    /// - **Lane 2 (out-of-range)**: rotates through the BOUNDED window
    ///   `[channel_count+1, channel_count+PUBLIC_CHANNEL_ID_MARGIN]` —
    ///   the space bulk enumeration alone can never reach, since
    ///   `channel_id` had no upper bound anywhere in the codebase before
    ///   this pass. Rounds 3.1 and 4 each tried to close this by making
    ///   an UNBOUNDED candidate set more expensive to pad (skip Private
    ///   rows; page through more of them) — a re-audit each time found
    ///   the same starvation recurring one layer down. Round 5 instead
    ///   bounds the SET SIZE at ingestion
    ///   (`messages::validation`/`messages::router`'s
    ///   `PUBLIC_CHANNEL_ID_MARGIN` check) and rotates through the
    ///   resulting small, fixed window exactly like Lane 3 does over
    ///   `1..=channel_count` — a full rotation now completes in a
    ///   bounded number of ticks regardless of how much an attacker pads
    ///   the window, because there is no slot outside it to hide in.
    /// - **Lane 3 (round-robin)**: re-walks the FULL id space via
    ///   `CHANNEL_VERIFY_ROUND_ROBIN_CURSOR`, wrapping at the end,
    ///   INCLUDING already-verified rows, up to its own reserved share.
    ///   This is what catches a channel ownership *transfer* whose
    ///   on-chain event fell into a permanent scan gap, or a row imported
    ///   via snapshot bootstrap that inherited another node's verdict
    ///   with no independent check (see `types::ChannelVerificationState`'s
    ///   doc comment — a bare bool that's never re-checked once true was
    ///   exactly the bug this lane exists to avoid reintroducing). A
    ///   row confirmed/corrected within the last
    ///   `POSITIVE_REVERIFY_COOLDOWN_SECS` is skipped for free (round 5,
    ///   security finding S4) — without this, budget was spent
    ///   re-confirming freshly-verified rows exactly as often as it was
    ///   spent on rows never independently checked at all.
    ///
    /// Skips the whole tick (no SC calls at all) while
    /// `self.backoff`/`consecutive_429s` indicate the scanner is already
    /// rate-limited — adding load to an already-429ing endpoint is
    /// counterproductive. Races every per-id verification against
    /// `shutdown_rx` so this never blocks a graceful shutdown for the
    /// whole tick's worth of throttled calls.
    async fn sweep_channel_verification(
        &self,
        shutdown_rx: &mut tokio::sync::broadcast::Receiver<()>,
    ) {
        if !self.channel_verify_config.enabled {
            return;
        }
        if !self.backoff.is_zero() {
            debug!(
                consecutive_429s = self.consecutive_429s,
                "sweep_channel_verification: scanner is already rate-limit-backing-off, skipping this tick"
            );
            return;
        }

        // Independent receiver (audit 2026-09-29, MEDIUM finding): a
        // `broadcast::Receiver` delivers each message once. If this
        // sweep's own shutdown checks raced the SAME `&mut shutdown_rx`
        // the outer scanner loop selects on, whichever arm won would
        // consume the one shutdown message — the outer loop's own
        // `shutdown_rx.recv()` arm would then never see it and hang until
        // the process is killed outright, not exit gracefully.
        // `resubscribe()` gives this sweep its own tap on the same
        // broadcast without stealing the original receiver's copy.
        let mut shutdown_rx = shutdown_rx.resubscribe();

        self.throttle_klever_request().await;
        let channel_count = match crate::chain::sc_views::get_stats(
            &self.http,
            &self.config.node_url,
            &self.config.contract_address,
        )
        .await
        {
            Ok((_user_count, channel_count, _protocol_version)) => channel_count,
            Err(e) => {
                warn!(error = %e, "sweep_channel_verification: getStats failed");
                return;
            }
        };
        // Cache for `messages::validation::validate_channel_create`'s
        // `PUBLIC_CHANNEL_ID_MARGIN` bound (audit round 5) — see
        // `state_keys::LAST_KNOWN_CHANNEL_COUNT`'s doc comment.
        if let Err(e) = self.storage.put_cf(
            cf::NODE_STATE,
            crate::storage::schema::state_keys::LAST_KNOWN_CHANNEL_COUNT,
            &channel_count.to_be_bytes(),
        ) {
            warn!(error = %e, "sweep_channel_verification: caching channel_count failed");
        }

        let total_budget = self.channel_verify_config.max_retriggers_per_sweep;
        let scan_cap = self.channel_verify_config.sweep_batch_size as u64;

        // Round-4 finding: a single SHARED budget drained by lanes in
        // priority order let an earlier lane permanently starve a later
        // one. Round-5 re-audit finding: the round-4 partition could
        // still zero a lane at small-but-plausible configs. Both fixed
        // in `partition_sweep_budget` (see its own doc comment) —
        // guarantees every lane a floor of 1 whenever `total >= 3`,
        // enforced unreachable-below-3 by `config::validate`'s own floor.
        let (lane1_budget, lane2_budget, lane3_budget) = partition_sweep_budget(total_budget);

        // Lane 1 (priority): every id newer than the persisted high-water
        // mark. Capped at `scan_cap` LOCAL considerations per tick too
        // (audit 2026-09-29, HIGH finding) — `verify_one_channel_creator`
        // returning 0 for "no local row" does no `.await` at all, so
        // without this cap a node whose local rows are sparse relative to
        // `channel_count` (fresh node, mid-bootstrap, or one that gapped a
        // large historical range) would run an unbounded, non-yielding
        // tight loop of local RocksDB reads.
        let high_water = read_u64_node_state(
            &self.storage,
            crate::storage::schema::state_keys::CHANNEL_VERIFY_HIGH_WATER,
        );
        let mut id = high_water.saturating_add(1);
        let mut considered = 0u64;
        let mut lane1_spent = 0usize;
        // Round-6 fix (security finding S2): track the first DEFERRED id
        // separately from the loop cursor. `id` keeps advancing past a
        // deferred one so this tick still reaches genuinely new ids
        // beyond it (budget permitting) — but `high_water` must stop
        // BEFORE the first deferred id, not at wherever the loop happened
        // to end, so next tick re-examines it instead of forfeiting it to
        // Lane 3. See `VerifyStep`'s doc comment for why "no RPC spent"
        // isn't the same as "safe to advance past."
        let mut first_deferred: Option<u64> = None;
        while id <= channel_count && lane1_spent < lane1_budget && considered < scan_cap {
            let step = tokio::select! {
                r = self.verify_one_channel_creator(id) => r,
                _ = shutdown_rx.recv() => {
                    info!("sweep_channel_verification: shutting down mid-priority-lane");
                    return;
                }
            };
            if step.deferred && first_deferred.is_none() {
                first_deferred = Some(id);
            }
            lane1_spent += step.rpc_calls as usize;
            considered += 1;
            id += 1;
        }
        // Advance high-water to the last id actually LOOKED AT and NOT
        // deferred (whether or not it spent budget) — not the same as
        // "verified", but correct for this lane's purpose: an id checked
        // and found to have no local row yet needs no further attention
        // from THIS lane once a local row does eventually appear. A
        // LATE-arriving local `ChannelCreate` for such an id (the case
        // this comment used to describe an out-of-band queue for, in
        // rounds 3.1-4) now falls back to Lane 3's own round-robin
        // cadence — removed in round 5 after two successive attempts at
        // a dedicated fast path (a global-cursor rewind, then a capped
        // per-id queue) each turned out to be their own
        // attacker-exploitable resource. See `messages::router`'s
        // `ChannelCreate` handler for the full reasoning.
        let new_high_water = match first_deferred {
            Some(deferred_id) => deferred_id.saturating_sub(1),
            None => id.saturating_sub(1),
        };
        if new_high_water > high_water {
            if let Err(e) = self.storage.put_cf(
                cf::NODE_STATE,
                crate::storage::schema::state_keys::CHANNEL_VERIFY_HIGH_WATER,
                &new_high_water.to_be_bytes(),
            ) {
                warn!(error = %e, "sweep_channel_verification: high-water write failed");
            }
        }

        // Lane 2 (out-of-range) — the case bulk enumeration alone can
        // NEVER reach: `channel_id` is fully attacker-controlled, so an
        // attacker who picks an id BEYOND `channel_count` — including the
        // very next one about to be legitimately minted — is invisible to
        // a walk that only ever covers `1..=channel_count`.
        //
        // Round 5 (fourth pass on this specific lane): rounds 3.1 and 4
        // each tried to close this by making an unbounded out-of-range
        // candidate set more EXPENSIVE to pad (skip Private rows; page
        // through more of them) — a re-audit each time found the same
        // starvation recurring one layer down, since the underlying set
        // size was never actually bounded. This pass instead bounds the
        // SET SIZE at ingestion (`messages::validation`'s
        // `PUBLIC_CHANNEL_ID_MARGIN`, enforced in `messages::router`'s
        // `ChannelCreate` handler) and rotates through the resulting
        // small, FIXED-size window exactly like Lane 3 already does over
        // `1..=channel_count` — `next_out_of_range_id`'s wraparound, and
        // `verify_one_channel_creator`'s own no-local-row branch making an
        // empty id free to pass over. A full rotation now completes in a
        // bounded number of ticks (`PUBLIC_CHANNEL_ID_MARGIN` at most,
        // divided by `lane2_budget`) regardless of how much an attacker
        // pads the window — nothing in it can hide behind anything else
        // in it forever, because there is no 51st slot to hide in.
        //
        // No explicit Private-row skip needed here (unlike rounds 3.1/4):
        // `PRIVATE_CHANNEL_ID_FLOOR` (2^32) keeps every legitimately-
        // validated Private id far outside this small near-the-frontier
        // window, so this lane will not encounter one in normal
        // operation. If that floor is ever removed or weakened, this lane
        // degrades to wasting occasional RPC on such rows — not a
        // reintroduction of the starvation this pass closes.
        if lane2_budget > 0 {
            let mut oor_cursor = read_u64_node_state(
                &self.storage,
                crate::storage::schema::state_keys::CHANNEL_VERIFY_OUT_OF_RANGE_CURSOR,
            );
            let mut lane2_spent = 0usize;
            let mut considered = 0u64;
            while considered < PUBLIC_CHANNEL_ID_MARGIN && lane2_spent < lane2_budget {
                oor_cursor = next_out_of_range_id(oor_cursor, channel_count);
                let step = tokio::select! {
                    r = self.verify_one_channel_creator(oor_cursor) => r,
                    _ = shutdown_rx.recv() => {
                        info!("sweep_channel_verification: shutting down mid-out-of-range-lane");
                        return;
                    }
                };
                lane2_spent += step.rpc_calls as usize;
                considered += 1;
            }
            if let Err(e) = self.storage.put_cf(
                cf::NODE_STATE,
                crate::storage::schema::state_keys::CHANNEL_VERIFY_OUT_OF_RANGE_CURSOR,
                &oor_cursor.to_be_bytes(),
            ) {
                warn!(error = %e, "sweep_channel_verification: out-of-range cursor write failed");
            }
        }

        // Lane 3 (round-robin) — its own reserved share; no longer
        // dependent on what Lanes 0-2 left over (round-4 fix — see the
        // partitioning comment above).
        if lane3_budget == 0 || channel_count == 0 {
            return;
        }
        let mut rr_cursor = read_u64_node_state(
            &self.storage,
            crate::storage::schema::state_keys::CHANNEL_VERIFY_ROUND_ROBIN_CURSOR,
        );
        let mut considered = 0u64;
        let mut lane3_spent = 0usize;
        while considered < scan_cap && lane3_spent < lane3_budget {
            rr_cursor = next_round_robin_id(rr_cursor, channel_count);
            let step = tokio::select! {
                r = self.verify_one_channel_creator(rr_cursor) => r,
                _ = shutdown_rx.recv() => {
                    info!("sweep_channel_verification: shutting down mid-round-robin-lane");
                    return;
                }
            };
            lane3_spent += step.rpc_calls as usize;
            considered += 1;
        }
        if let Err(e) = self.storage.put_cf(
            cf::NODE_STATE,
            crate::storage::schema::state_keys::CHANNEL_VERIFY_ROUND_ROBIN_CURSOR,
            &rr_cursor.to_be_bytes(),
        ) {
            warn!(error = %e, "sweep_channel_verification: round-robin cursor write failed");
        }
    }

    /// Re-verify a single channel's `creator` against the SC and apply the
    /// result via `Storage::apply_channel_verification_result` (locked,
    /// re-reads fresh state under the lock, tombstone-aware — audit
    /// 2026-09-29 replaces the first attempt's unlocked read-await-write,
    /// which could silently revert a concurrent member change, a
    /// `ChannelUpdate`'s `channel_type`/`encryption_enabled` flip, or
    /// resurrect a channel deleted during the await).
    ///
    /// Returns a `VerifyStep`: `rpc_calls` for the sweep's request-budget
    /// accounting (0, 1, or 2 — a correction needing `getChannelInfo`'s
    /// authoritative type costs 2), and `deferred` for Lane 1's
    /// high-water bookkeeping specifically (see `VerifyStep`'s own doc
    /// comment — round-6 audit finding, S2: an id can carry verification
    /// state from BEFORE Lane 1 ever reaches it, e.g. Lane 2 flagged it
    /// while still out-of-range, so "no RPC spent" does not mean "safe to
    /// advance past").
    /// **Correction-only**: never synthesizes a new row for an id the SC
    /// confirms exists but this node has never locally recorded — seeding
    /// one here would make the historical scanner's `ChannelCreated`
    /// handler think the row isn't new and permanently skip seeding
    /// `CHANNEL_MEMBERS`/`TOTAL_CHANNELS` for it (traced precisely:
    /// `is_new` there is `!exists_cf(CHANNELS)`).
    async fn verify_one_channel_creator(&self, channel_id: u64) -> VerifyStep {
        let existing = match self.storage.get_cf(cf::CHANNELS, &channel_id.to_be_bytes()) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                // No live row — either genuinely never locally known (no
                // RPC spent, nothing to do), or tombstoned, in which case
                // it's worth a poisoning cross-check (see that method's
                // doc comment for what this can and can't catch). Never
                // "deferred": there is nothing pending on this id that a
                // later lane pass would need to catch that THIS pass
                // missed — the no-local-row case is a stable answer.
                return VerifyStep {
                    rpc_calls: if self.check_tombstoned_channel_for_poisoning(channel_id).await {
                        1
                    } else {
                        0
                    },
                    deferred: false,
                };
            }
            Err(_) => return VerifyStep::default(),
        };
        let meta: serde_json::Value = match serde_json::from_slice::<serde_json::Value>(&existing) {
            Ok(m) if m.is_object() => m,
            // Corrupt or non-object row: check shape BEFORE spending an
            // RPC call, not after (the first attempt wasted a throttled
            // call + a real SC request on a row it was always going to
            // discard).
            _ => return VerifyStep::default(),
        };
        // Cooldown (audit 2026-09-29 round 3.1): skip re-spending an RPC
        // on an id whose last check already came back `NoOnChainBacking`
        // within `NO_BACKING_RECHECK_COOLDOWN_SECS` — without this, a
        // handful of standing out-of-range claims (or a legitimate
        // channel mid-on-chain-confirmation) get re-verified and
        // re-`warn!`-alerted on EVERY tick forever. A genuine on-chain
        // confirmation bypasses this entirely: the historical scanner's
        // `mark_channel_creator_verified` overwrites this state directly
        // the moment it actually scans the real event. DEFERRED, not a
        // stable answer — Lane 1 must not advance `high_water` past this
        // id (round-6 fix): the row could be a genuine channel that was
        // squatted while still out-of-range and just became real, and
        // demoting it to Lane 3's cadence (weeks to years at scale)
        // defeats the entire point of the priority lane for exactly the
        // ids that matter most.
        let vstate = self.storage.read_channel_verification_state(channel_id);
        let now = now_unix_secs();
        if should_skip_no_backing_recheck(&vstate, now) {
            return VerifyStep { rpc_calls: 0, deferred: true };
        }
        // Round-5 security audit finding (S4): with no positive-side
        // skip, Lane 3 (round-robin) spends its budget re-confirming rows
        // the historical scanner (or an earlier lane pass) verified only
        // seconds ago, just as often as it spends it on rows that have
        // NEVER been independently checked — the actual squat
        // candidates. A never-verified row (`creator_verified_at ==
        // None`) is NEVER skipped by this — only a row confirmed within
        // the last day is, redirecting budget toward genuinely stale or
        // never-checked rows over time. Also DEFERRED for the same
        // high-water reason as above, though in practice this specific
        // branch rarely fires for a genuinely-new Lane-1 id (a fresh id
        // has no prior confirmation to be recent about) — the case it
        // protects is a row Lane 3 or the historical scanner confirmed
        // moments before Lane 1 got there.
        if should_skip_recent_positive_reverify(&vstate, now) {
            return VerifyStep { rpc_calls: 0, deferred: true };
        }

        let stored_creator = meta
            .get("creator")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // The row's OWN claimed type — used only to decide whether a
        // `None` result below is suspicious or expected (see that branch),
        // and whether a correction below needs a second call to fetch the
        // authoritative type. Never used to decide whether to check this
        // id at all: walking EVERY id regardless of the local claim is
        // what closes the "just self-label Private to dodge verification"
        // bypass.
        let stored_channel_type = resolve_channel_type(&meta);

        self.throttle_klever_request().await;
        let verified = match crate::chain::sc_views::get_channel_creator(
            &self.http,
            &self.config.node_url,
            &self.config.contract_address,
            channel_id,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(channel_id, error = %e, "sweep_channel_verification: getChannelCreator call failed");
                // An RPC WAS attempted — still counts against budget, and
                // not "deferred": a transport error isn't a cooldown, so
                // there's nothing to protect from a premature high-water
                // advance beyond the ordinary retry-next-tick behavior.
                return VerifyStep { rpc_calls: 1, deferred: false };
            }
        };

        let Some(verified_creator) = verified else {
            // The SC has no such channel right now — a live signal, not
            // lag-dependent. Expected and unremarkable for a genuinely
            // private channel (Private never exists on-chain at all, and
            // a private channel's id is client-chosen, so it can land
            // anywhere in this enumeration space). Only worth flagging
            // when the LOCAL row itself claims to be Public/ReadPublic —
            // that combination (claims public, SC has never heard of it)
            // is the actual "fabricated public-channel claim" signal.
            if stored_channel_type == 0 || stored_channel_type == 1 {
                warn!(
                    channel_id,
                    stored_creator = %stored_creator,
                    "sweep_channel_verification: channel claims to be public but the SC \
                     has no record of it — possible fabricated public-channel claim"
                );
                self.bump_channel_verification_alerts();
                if let Err(e) = self.storage.apply_channel_verification_result(
                    channel_id,
                    crate::storage::rocks::ChannelVerificationOutcome::NoOnChainBacking,
                    now_unix_secs(),
                ) {
                    warn!(channel_id, error = %e, "sweep_channel_verification: applying verification result failed");
                }
            }
            return VerifyStep { rpc_calls: 1, deferred: false };
        };

        // Reaching here means the SC DOES have a record for this id — which
        // is only ever possible for a genuinely on-chain-created channel,
        // structurally always Public or ReadPublic (the SC has no concept
        // of a private channel). This does NOT mean the row's CURRENT
        // Public<->ReadPublic distinction should be resynced from it —
        // that's L2-authoritative and meant to diverge from the immutable
        // on-chain snapshot (see `ChannelVerificationOutcome::Confirmed`'s
        // doc comment).
        let rpc_calls = 1u32;
        let outcome = if verified_creator == stored_creator {
            crate::storage::rocks::ChannelVerificationOutcome::Confirmed
        } else {
            // The actual squat-or-transfer-caught case: the stored creator
            // disagrees with the SC's own live record. Correct it —
            // mirrors exactly what ChannelCreated's on-chain merge already
            // does when the historical scan eventually reaches this event.
            // (Round 6, S4: no longer fetches `getChannelInfo` to also
            // resync `channel_type` for a currently-Private row — see
            // `ChannelVerificationOutcome::Corrected`'s doc comment for
            // why that stopped being safe once `PRIVATE_CHANNEL_ID_FLOOR`
            // closed the bypass it was meant to catch.)
            if !stored_creator.is_empty() {
                warn!(
                    channel_id,
                    stored_creator = %stored_creator,
                    verified_creator = %verified_creator,
                    "sweep_channel_verification: on-chain creator disagrees with stored \
                     creator — correcting (possible squatted channel_id)"
                );
            } else {
                // No prior `creator` field at all — not an alarming
                // "possible squat," just a first confirmation.
                debug!(
                    channel_id,
                    verified_creator = %verified_creator,
                    "sweep_channel_verification: confirming creator for a row with no prior stored value"
                );
            }
            crate::storage::rocks::ChannelVerificationOutcome::Corrected { verified_creator }
        };

        match self
            .storage
            .apply_channel_verification_result(channel_id, outcome, now_unix_secs())
        {
            Ok(true) => {
                // Round 6, S4: detected, not auto-corrected — a
                // currently-Private row whose id turns out to have real
                // on-chain backing. Could be a pre-`PRIVATE_CHANNEL_ID_
                // FLOOR` legacy row (this node can no longer tell it
                // apart from a genuinely legitimate old private
                // channel), so the row is left untouched; surfaced for
                // operator review only. Fires for BOTH outcomes now
                // (round 8, CRITICAL): a mismatched creator (`Corrected`)
                // is the accidental-collision shape, but a MATCHING
                // creator (`Confirmed`) is exactly what a deliberate
                // attacker would arrange (sign both the local Private
                // create and the real on-chain create with the same
                // wallet) specifically to dodge detection — any on-chain
                // backing at all for a claimed-Private id is anomalous,
                // regardless of whether the creator happens to match.
                warn!(
                    channel_id,
                    stored_channel_type,
                    "sweep_channel_verification: a currently-Private channel's id has real \
                     on-chain backing — possible pre-floor legacy self-label, or a legitimate \
                     collision. NOT automatically corrected; needs operator review."
                );
                self.bump_channel_verification_alerts();
            }
            Ok(false) => {}
            Err(e) => {
                warn!(channel_id, error = %e, "sweep_channel_verification: applying verification result failed");
            }
        }
        VerifyStep { rpc_calls, deferred: false }
    }

    /// Detection-only cross-check for delete-tombstone poisoning (audit
    /// 2026-09-29, "C1"): an attacker sends `ChannelCreate` for a
    /// not-yet-real public channel_id (trusted as creator with no
    /// on-chain check), then immediately `ChannelDelete`s it — which
    /// `channel_creator_check` authorizes, since the attacker genuinely
    /// is the LOCAL row's creator. The tombstone this leaves behind
    /// permanently blocks the id's real future on-chain creation (both
    /// the chain scanner's `ChannelCreated` handler and the L2
    /// `ChannelCreate` handler refuse to (re)create a tombstoned id).
    ///
    /// **This is detection, not prevention.** The correct synchronous fix
    /// — a live `getChannelCreator` check before the delete is allowed to
    /// proceed at all — would require making `messages::router`'s
    /// `update_indexes` (and its whole synchronous call chain,
    /// `process_message_inner` and up) `async`, a separate, much larger
    /// and riskier refactor of the core message-ingest path that isn't
    /// being rushed into this pass. Instead, `tombstone_channel` now
    /// records `deleted_by` (the L2 deleter's wallet, when known), and
    /// this sweep cross-checks it against the SC's live record: if the
    /// SC confirms a REAL creator for a tombstoned id who is NOT who
    /// deleted it locally, that's the poisoning signature — surfaced as a
    /// loud `warn!` for operator visibility, within one sweep cycle. No
    /// automatic reversal (restoring a tombstoned channel safely is its
    /// own hard problem — out of scope here). A tombstoned id whose
    /// deleter DOES match the SC's confirmed creator is the normal,
    /// frequent, entirely legitimate case (an owner deleting their own
    /// real channel) and is silently left alone.
    async fn check_tombstoned_channel_for_poisoning(&self, channel_id: u64) -> bool {
        let key = channel_id.to_be_bytes();
        let tombstone = match self.storage.get_cf(cf::DELETED_CHANNELS, &key) {
            Ok(Some(bytes)) => bytes,
            _ => return false, // not tombstoned either — genuinely nothing here
        };
        let mut tombstone_meta: serde_json::Value = match serde_json::from_slice(&tombstone) {
            Ok(v) => v,
            Err(_) => return false, // corrupt tombstone — nothing sane to do
        };
        // Cache: the answer can never change after the first successful
        // check — the tombstone itself is immutable, and a deleted
        // channel's on-chain creator cannot change either (the SC has no
        // way to transfer a channel this node no longer has any local
        // record of soliciting a transfer for — the only path that
        // reassigns `channel_creator` is `transferChannel`, and nothing
        // about a LOCAL delete affects on-chain state at all, but there is
        // no L2 mechanism to target a transfer at a locally-tombstoned id
        // either way). Re-asking every round-robin pass forever wasted an
        // RPC on every legitimate delete for zero new information (audit
        // 2026-09-29, code-review finding) — stamp once, skip forever after.
        if tombstone_meta
            .get("poison_checked")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return false;
        }
        // Round 5 added, and round 6 REVERTED, an "admin delete" exemption
        // here (`admin_delete` flag, `Storage::mark_tombstone_as_admin_
        // delete`): both a code and a security auditor independently
        // found the REST delete route (`api/routes.rs::delete_channel`)
        // is plain Klever-wallet auth whose ONLY authorization check is
        // `creator == auth_user.address` against the LOCAL, unverified
        // CHANNELS row — the exact forgeable claim this whole check
        // exists to catch — so the exemption let any squatter silence
        // detection of their own attack by calling that endpoint instead
        // of the signed-envelope path. The stated false-positive problem
        // it was built to fix does not occur in the first place: this
        // route's own creator check already guarantees `deleted_by ==
        // real_creator` for a genuine on-chain channel (the scanner
        // always writes the on-chain creator into the row), so no
        // exemption was ever needed.
        let deleted_by = tombstone_meta
            .get("deleted_by")
            .and_then(|d| d.as_str())
            .map(str::to_string);
        // No recorded deleter (chain-verified claim-consumption path, or a
        // tombstone written before this field existed) — nothing to
        // compare against, and this path is either already chain-verified
        // or too old to usefully act on. Still cache "checked" so this
        // branch, too, is a one-time cost.
        let Some(deleted_by) = deleted_by else {
            self.mark_tombstone_poison_checked(&key, &mut tombstone_meta);
            return false;
        };

        self.throttle_klever_request().await;
        let verified = match crate::chain::sc_views::get_channel_creator(
            &self.http,
            &self.config.node_url,
            &self.config.contract_address,
            channel_id,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(channel_id, error = %e, "check_tombstoned_channel_for_poisoning: getChannelCreator call failed");
                // Don't cache on a transport error — genuinely unknown,
                // worth retrying next cycle rather than concluding "clean."
                return true;
            }
        };

        // Round-4 security audit finding (BLOCKING): `None` here is NOT a
        // conclusive answer — it means "the SC has no record for this id
        // right now," which for an id above the current on-chain frontier
        // is simply "not minted yet," not "nothing to worry about."
        // Unconditionally caching `poison_checked` on `None` (the previous
        // version of this method) meant an id checked via Lane 2 (while
        // `channel_id > channel_count`, where the SC can only EVER return
        // `None`) got permanently marked "checked" — so once the real
        // on-chain channel is eventually minted at that id and Lane 1/Lane
        // 3 reach it (`verify_one_channel_creator`'s own no-local-row
        // branch calls this same method), the cached flag skipped the
        // check at EXACTLY the moment it could finally produce a real
        // answer, permanently defeating tombstone-poisoning detection for
        // any id examined while still out of range. Only cache on a
        // definitive `Some` — match or mismatch, either way the SC has
        // spoken and there is nothing more to learn by asking again.
        let Some(real_creator) = &verified else {
            return true;
        };
        if *real_creator != deleted_by {
            warn!(
                channel_id,
                deleted_by = %deleted_by,
                real_creator = %real_creator,
                "check_tombstoned_channel_for_poisoning: a tombstoned channel_id has \
                 real on-chain backing under a DIFFERENT creator than whoever deleted \
                 it locally — possible squat-then-delete poisoning attempt. NOT \
                 automatically reversed; needs operator review."
            );
            self.bump_channel_verification_alerts();
        }
        self.mark_tombstone_poison_checked(&key, &mut tombstone_meta);
        true
    }

    /// Stamp `poison_checked: true` onto an already-parsed `DELETED_CHANNELS`
    /// value and write it back, best-effort. Shared by both cacheable exit
    /// paths of `check_tombstoned_channel_for_poisoning`.
    fn mark_tombstone_poison_checked(&self, key: &[u8], tombstone_meta: &mut serde_json::Value) {
        if let Some(obj) = tombstone_meta.as_object_mut() {
            obj.insert("poison_checked".into(), serde_json::json!(true));
            if let Ok(bytes) = serde_json::to_vec(tombstone_meta) {
                if let Err(e) = self.storage.put_cf(cf::DELETED_CHANNELS, key, &bytes) {
                    warn!(error = %e, "check_tombstoned_channel_for_poisoning: caching check result failed");
                }
            }
        }
    }
}

/// Result of one `ChainScanner::verify_one_channel_creator` call.
///
/// `deferred` (round 6, security finding S2) distinguishes "this id was
/// skipped by a cooldown, and a later pass MUST still reach it" from
/// "this id has a genuinely stable answer for now, safe to advance
/// past." Lane 1 (priority) uses this to avoid advancing
/// `CHANNEL_VERIFY_HIGH_WATER` past a deferred id — an id can carry
/// verification state from BEFORE Lane 1 ever walked to it (e.g. Lane 2
/// flagged it while it was still out-of-range, and it became real
/// moments before Lane 1 arrived), so "no RPC spent this call" does NOT
/// mean "nothing more to do here." Advancing past it anyway would demote
/// the id to Lane 3's round-robin cadence (documented at weeks-to-years
/// at scale) for exactly the case — a squat caught pre-mint, now real —
/// the priority lane exists to close fast.
#[derive(Debug, Clone, Copy, Default)]
struct VerifyStep {
    rpc_calls: u32,
    deferred: bool,
}

/// Read a `NODE_STATE` value as a big-endian `u64`, defaulting to `0` on any
/// absent/malformed/error case — used for the verification sweep's cursors,
/// where "0" naturally means "start from the beginning."
fn read_u64_node_state(storage: &Storage, key: &[u8]) -> u64 {
    storage
        .get_cf(cf::NODE_STATE, key)
        .ok()
        .flatten()
        .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

/// Pure step function for the round-robin verification lane's wraparound:
/// given the last-checked id and the current `channel_count`, returns the
/// NEXT id to check — wraps from `channel_count` back to `1`. The caller
/// (`sweep_channel_verification`) is responsible for never calling this
/// when `channel_count == 0` (nothing minted yet); this function still
/// returns a defined value (`0`) rather than panicking if it ever is.
fn next_round_robin_id(cursor: u64, channel_count: u64) -> u64 {
    if channel_count == 0 {
        return 0;
    }
    if cursor >= channel_count {
        1
    } else {
        cursor + 1
    }
}

/// `true` if a CHANNELS row's `channel_type` resolves to Public(0) or
/// ReadPublic(1) — mirrors `messages::router`'s tolerant numeric-or-legacy-
/// string parse (`check_readonly_channel`, router.rs ~1474-1486) and its
/// same "default to Public on anything unparseable" convention, so this
/// stays consistent with how the rest of the codebase already treats a
/// malformed/missing `channel_type` field. Compares as `u64` — NOT `as u8`
/// (audit 2026-09-29 finding: the first attempt's cast truncated wrong,
/// e.g. `258 → 2`, silently misclassifying a malformed value as Private
/// instead of falling back to the documented Public default).
fn resolve_channel_type(meta: &serde_json::Value) -> u64 {
    match meta.get("channel_type") {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(serde_json::Value::String(s)) => match s.as_str() {
            "Public" => 0,
            "ReadPublic" => 1,
            "Private" => 2,
            _ => 0,
        },
        _ => 0,
    }
}

/// Outcome of `merge_channel_created_into_existing` and (round 9)
/// `apply_channel_transfer_to_existing` — shared since both are the same
/// shape: merge an on-chain event's authoritative fields into an existing
/// local `CHANNELS` row, with the same currently-Private collision guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelFieldMergeOutcome {
    /// The merge was applied — `meta` now reflects the on-chain fields.
    Merged,
    /// `meta` is currently Private; left COMPLETELY untouched (round 7 —
    /// see the caller's doc comment for why this mirrors
    /// `apply_channel_verification_result`'s detect-don't-correct
    /// posture for the same collision).
    PrivateCollisionDetected,
    /// `meta` parsed as JSON but isn't an object — nothing sane to merge.
    NotAnObject,
}

/// Merge an on-chain `ChannelCreated` event's authoritative fields into an
/// EXISTING local `CHANNELS` row's JSON in place (re-scan / catch-up path
/// — a fresh row is built separately by the caller as a plain
/// `ChannelRecord`). Pure so this can be unit-tested without the HTTP
/// mocking this crate otherwise has no harness for (`ScEvent::
/// ChannelCreated`'s handler needs a live `getChannelBySlug` call to
/// resolve `channel_id` before it can even reach this point).
///
/// Never writes `channel_type` when `meta` is NOT currently Private — the
/// Public<->ReadPublic distinction is L2-authoritative
/// (`messages::router`'s `ChannelUpdate`) and meant to diverge from the
/// immutable on-chain snapshot; overwriting it here on every re-scan was
/// round 2's rejected design, reintroduced in this sibling code path and
/// caught by round 6's audit (`apply_channel_verification_result`'s
/// `Confirmed` outcome already protects the identical invariant on the
/// sweep's side). When `meta` IS currently Private, round 7's audit found
/// `creator`/`slug`/`created_at` were STILL unconditionally overwritten —
/// the identical "self-label Private to escape the trust boundary"
/// collision this feature closes elsewhere (a legacy pre-`PRIVATE_
/// CHANNEL_ID_FLOOR` row colliding with a real on-chain channel would
/// have its ownership and identity silently reassigned every re-scan) —
/// so that case now touches nothing at all and reports it via the
/// returned outcome instead.
fn merge_channel_created_into_existing(
    meta: &mut serde_json::Value,
    channel_id: u64,
    slug: &str,
    creator: &str,
    timestamp: u64,
) -> ChannelFieldMergeOutcome {
    if resolve_channel_type(meta) == 2 {
        return ChannelFieldMergeOutcome::PrivateCollisionDetected;
    }
    let Some(obj) = meta.as_object_mut() else {
        return ChannelFieldMergeOutcome::NotAnObject;
    };
    obj.insert("channel_id".into(), serde_json::json!(channel_id));
    obj.insert("slug".into(), serde_json::json!(slug));
    obj.insert("creator".into(), serde_json::json!(creator));
    obj.insert("created_at".into(), serde_json::json!(timestamp));
    // Default missing L2-only fields without overwriting present ones.
    obj.entry("display_name").or_insert(serde_json::Value::Null);
    obj.entry("description").or_insert(serde_json::Value::Null);
    obj.entry("member_count").or_insert(serde_json::json!(0));
    ChannelFieldMergeOutcome::Merged
}

/// Apply an on-chain `ChannelTransferred` event's new creator into an
/// EXISTING local `CHANNELS` row's JSON in place. Pure, same reasoning
/// and testability rationale as `merge_channel_created_into_existing`.
///
/// Round 9 audit finding (CRITICAL, pre-existing — not introduced by
/// this feature's own rounds, just never examined until round 9's
/// "check every sibling arm for the same guard" sweep, prompted by
/// round 8 naming this exact bug shape): this handler used to
/// unconditionally overwrite `creator` with no currently-Private check
/// at all, unlike `ChannelCreated`'s sibling merge (fixed in rounds
/// 6-7). `is_channel_creator`/`channel_creator_check`
/// (`messages::router`) gate delete/ban/update/invite authority purely
/// on `CHANNELS.creator`, with no `channel_type` distinction — so for a
/// pre-`PRIVATE_CHANNEL_ID_FLOOR` legacy row colliding with a real
/// on-chain id, whoever controls the on-chain side of that id could
/// call the SC's transfer function to move it to ANY address they
/// choose, and this handler would silently hand that address
/// delete/ban/update/invite authority over an unrelated real user's
/// currently-Private channel — worse than the `Confirmed`/`Corrected`
/// gap round 8 fixed, since it needs no coincidence of the victim's own
/// signing key at all, only that the attacker controls the on-chain
/// transfer. Same fix as `merge_channel_created_into_existing`: detect,
/// alert, touch nothing.
fn apply_channel_transfer_to_existing(meta: &mut serde_json::Value, to: &str) -> ChannelFieldMergeOutcome {
    if resolve_channel_type(meta) == 2 {
        return ChannelFieldMergeOutcome::PrivateCollisionDetected;
    }
    let Some(obj) = meta.as_object_mut() else {
        return ChannelFieldMergeOutcome::NotAnObject;
    };
    obj.insert("creator".into(), serde_json::json!(to));
    ChannelFieldMergeOutcome::Merged
}

/// Where a transaction's block falls relative to the scan's intended
/// `[start, end]` range. The Klever testnet API's `startBlock`/`endBlock`
/// query params are silently not honored (see `process_range_paged`'s doc
/// comment) — the server just returns its most recent matching
/// transactions, newest-first, regardless of the requested range. Callers
/// must classify and act on each transaction themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangePosition {
    /// Newer than `end` — not this range's concern; a later tick's range
    /// will cover it once it advances that far.
    TooNew,
    /// Within `[start, end]` — process it.
    InRange,
    /// Older than `start` — the scan has walked past its intended range.
    /// Given newest-first ordering, every remaining entry on this page and
    /// every subsequent page can only be older still, so there is nothing
    /// further to find in-range and paging can stop.
    TooOld,
}

fn classify_block_range_position(block_num: u64, start: u64, end: u64) -> RangePosition {
    if block_num > end {
        RangePosition::TooNew
    } else if block_num < start {
        RangePosition::TooOld
    } else {
        RangePosition::InRange
    }
}

/// Outcome of `process_range_paged` for one `[start, end]` attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PageOutcome {
    /// Fully processed — a short page or a walked-past-start terminated it.
    Complete,
    /// Hit `MAX_PAGES` with enough remaining budget, once the target range
    /// was reached, to make subdividing plausibly worthwhile — this range
    /// genuinely holds more matching transactions than the page budget
    /// covers. Subdividing narrows real work.
    CapExceededDense,
    /// Hit `MAX_PAGES` without ever reaching the target range with
    /// meaningful budget left (see `classify_cap_outcome`) — either every
    /// page was still newer than `end`, or it was reached too late (e.g.
    /// page ~48/50) for narrowing the range to help. Since the API ignores
    /// `startBlock`/`endBlock` and always returns the newest transactions
    /// first (see `process_range_paged` doc comment), this means the target
    /// range is simply too far from the current chain tip to reach within
    /// the page budget — a tip-distance problem, not a range-density one.
    /// Subdividing the block range does nothing to reduce that distance:
    /// every sub-range would independently re-walk the identical
    /// newest-first pages and hit the identical cap (audit 2026-09-28:
    /// this held even for the original bare-bool version whenever the
    /// range was reached late, reproducing the same combinatorial
    /// explosion this fix exists to remove — see `classify_cap_outcome`).
    /// Treat as unreachable this attempt (mirrors the single-block
    /// pathological case below) instead of recursing.
    CapExceededTooDeep,
}

/// Decide `CapExceededDense` vs. `CapExceededTooDeep` once `process_range_paged`
/// hits `max_pages` without completing.
///
/// `first_in_range_page` is the 1-based page on which paging first reached
/// an in-range (or too-old) transaction, or `None` if every page was still
/// newer than `end`. Subdividing is only classified as worthwhile when at
/// least half the page budget remained AFTER reaching the target range —
/// reaching it with only a sliver of budget left (e.g. page 48 of 50) means
/// every subdivision would independently re-walk the same near-full prefix
/// of newer-than-target pages and hit the identical cap, so narrowing the
/// range buys nothing (audit 2026-09-28, boundary-misclassification finding
/// — a bare "was it ever reached" bool missed this case entirely).
fn classify_cap_outcome(first_in_range_page: Option<u64>, max_pages: u64) -> PageOutcome {
    let dense = first_in_range_page
        .map(|p| max_pages.saturating_sub(p) >= max_pages / 2)
        .unwrap_or(false);
    if dense {
        PageOutcome::CapExceededDense
    } else {
        PageOutcome::CapExceededTooDeep
    }
}

/// A single permanently-skipped chain-scan range (audit 2026-09-28) — see
/// `PageOutcome::CapExceededTooDeep`. Persisted so an operator (via
/// `MetricsSnapshot::klever_scan_gap_count`/`klever_scan_gap_blocks_total`)
/// can see this node's history has a real gap, instead of
/// `klever_sync_lag_blocks` silently reporting "fully synced" — that field
/// is computed from the same cursor that just advanced past the gap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapRecord {
    pub start: u64,
    pub end: u64,
    pub recorded_at: u64,
}

/// Max gap records retained — oldest dropped first once exceeded. A
/// healthy/reasonably-configured node should record few to none of these;
/// this bounds worst-case JSON-blob size on one that doesn't.
const MAX_CHAIN_SCAN_GAPS: usize = 500;

/// Read the persisted gap list — empty if none recorded, or on any
/// read/parse error. Never panics or propagates a hard failure: this is a
/// purely diagnostic list, not something correctness depends on.
pub fn read_chain_scan_gaps(storage: &Storage) -> Vec<GapRecord> {
    match storage.get_cf(
        cf::NODE_STATE,
        crate::storage::schema::state_keys::CHAIN_SCAN_GAPS,
    ) {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Read the monotonic lifetime total of blocks covered by every recorded
/// chain-scan gap — see `state_keys::CHAIN_SCAN_GAP_BLOCKS_TOTAL`'s doc
/// comment for why this is a separate counter from the capped
/// `read_chain_scan_gaps` list.
pub fn read_chain_scan_gap_blocks_total(storage: &Storage) -> u64 {
    read_u64_node_state(
        storage,
        crate::storage::schema::state_keys::CHAIN_SCAN_GAP_BLOCKS_TOTAL,
    )
}

/// Read the monotonic lifetime channel-verification-alerts counter — see
/// `state_keys::CHANNEL_VERIFICATION_ALERTS_TOTAL`'s doc comment.
pub fn read_channel_verification_alerts_total(storage: &Storage) -> u64 {
    read_u64_node_state(
        storage,
        crate::storage::schema::state_keys::CHANNEL_VERIFICATION_ALERTS_TOTAL,
    )
}

/// Split one tick's total `max_retriggers_per_sweep` budget into three
/// independent per-lane sub-budgets (Lane 0 — the pending-recheck queue —
/// was removed in round 5; see the queue-removal comment in
/// `messages::router`'s `ChannelCreate` handler), extracted from
/// `ChainScanner::sweep_channel_verification` for unit-testability.
///
/// Round-4 finding: a single shared budget drained in priority order let
/// an earlier lane permanently starve every lane below it. Round-5
/// re-audit finding: the round-4 fix's `(total/4).max(1)` allocation,
/// applied sequentially, could still starve LATER lanes at small-but-
/// entirely-plausible operator configs — `total <= 3` zeroed Lane 3 (the
/// ONLY lane catching a `ChannelTransferred` lost to a scan gap)
/// entirely, and the config-floor clamp of `1` produced `(0, 0, 1)` at the
/// time (now `(0, 0, 1)` collapses differently — see below), i.e. an
/// operator turning the budget down for cost reasons silently got a
/// SILENTLY DEGRADED security posture with no log line. Fixed by
/// guaranteeing each lane a floor of 1 BEFORE any lane gets a second
/// unit, so every lane is nonzero whenever `total >= 3` (matching the
/// number of lanes) — Lane 1 (priority — closes a NEW squat fast) is
/// guaranteed first, then Lane 2 (out-of-range), then Lane 3
/// (round-robin); any remaining budget beyond the three floors is split
/// with the remainder favoring Lane 3, same rationale as before (it
/// already tolerates a slow trickle by design). Returns `(lane1, lane2,
/// lane3)`; the three always sum to at most `total` (never more).
fn partition_sweep_budget(total: usize) -> (usize, usize, usize) {
    if total == 0 {
        return (0, 0, 0);
    }
    let mut remaining = total;
    let lane1_floor = 1.min(remaining);
    remaining -= lane1_floor;
    let lane2_floor = 1.min(remaining);
    remaining -= lane2_floor;
    let lane3_floor = 1.min(remaining);
    remaining -= lane3_floor;

    let lane_share = (remaining / 3).max(if remaining > 0 { 1 } else { 0 }).min(remaining);
    let lane1_extra = lane_share.min(remaining);
    remaining -= lane1_extra;
    let lane2_extra = lane_share.min(remaining);
    remaining -= lane2_extra;
    let lane3_extra = remaining;

    (lane1_floor + lane1_extra, lane2_floor + lane2_extra, lane3_floor + lane3_extra)
}

/// Pure cooldown decision, extracted from `ChainScanner::
/// verify_one_channel_creator` for unit-testability (audit 2026-09-29
/// round 3.1, MEDIUM finding: this round's new invariants had zero test
/// coverage). `true` means skip re-spending an RPC on this id.
fn should_skip_no_backing_recheck(
    vstate: &crate::chain::types::ChannelVerificationState,
    now: u64,
) -> bool {
    if !vstate.creator_verification_failed {
        return false;
    }
    match vstate.no_backing_checked_at {
        Some(checked_at) => now.saturating_sub(checked_at) < NO_BACKING_RECHECK_COOLDOWN_SECS,
        None => false,
    }
}

/// Pure cooldown decision for the POSITIVE side (audit round 5, security
/// finding S4): without this, Lane 3 spends its budget re-confirming a
/// row the historical scanner (or an earlier pass) verified moments ago
/// exactly as often as it spends it on a row that's NEVER been
/// independently checked — the actual squat candidates. `true` means
/// skip re-spending an RPC. A row with `creator_verified_at == None`
/// (never verified) is NEVER skipped by this, by construction — only an
/// id confirmed recently is, so budget shifts toward stale/unverified
/// rows over time.
fn should_skip_recent_positive_reverify(
    vstate: &crate::chain::types::ChannelVerificationState,
    now: u64,
) -> bool {
    if vstate.creator_verification_failed {
        return false; // a standing negative is `should_skip_no_backing_recheck`'s concern
    }
    match vstate.creator_verified_at {
        Some(verified_at) => now.saturating_sub(verified_at) < POSITIVE_REVERIFY_COOLDOWN_SECS,
        None => false,
    }
}

/// How far above the SC's current `channel_count` a Public/ReadPublic
/// `ChannelCreate` may claim its `channel_id` to be — enforced at
/// ingestion in `messages::router::MessageRouter::validate_channel_id_
/// margin`, against the cached `state_keys::LAST_KNOWN_CHANNEL_COUNT`.
///
/// Round 5 (fourth implementation pass on Lane 2 specifically): rounds
/// 3.1 and 4 each tried to close Lane 2's starvation by making padding
/// more EXPENSIVE (skip Private rows, page through more of them) without
/// ever bounding the SIZE of the out-of-range candidate set itself — a
/// re-audit each time found the same shape recurring one layer down,
/// because the underlying resource (however many out-of-range rows an
/// attacker can plant) stayed unbounded. This constant, and the
/// ingestion-time rejection it drives, removes that resource instead:
/// Lane 2's rotation window (`next_out_of_range_id`, below) can now NEVER
/// contain more than this many candidates, so a full rotation — and
/// therefore a guaranteed check of anything planted in it — completes in
/// a bounded number of ticks, not "eventually, maybe never." Chosen small
/// relative to the scanner's own global RPC throttle
/// (`KLEVER_REQUEST_MIN_SPACING_MS`, shared with block-height polling and
/// every other Klever call this scanner makes) — legitimate channel
/// creation is documented elsewhere as "almost always 0-1 ids per tick,"
/// so this is generous headroom, not a realistic ceiling on legitimate
/// traffic.
pub const PUBLIC_CHANNEL_ID_MARGIN: u64 = 50;

/// Lane 2's round-robin step, mirroring `next_round_robin_id` exactly but
/// over the BOUNDED out-of-range window `[channel_count+1,
/// channel_count+PUBLIC_CHANNEL_ID_MARGIN]` instead of `[1,
/// channel_count]`. Pure/unit-tested for the same reason as its sibling.
fn next_out_of_range_id(cursor: u64, channel_count: u64) -> u64 {
    let low = channel_count.saturating_add(1);
    let high = channel_count.saturating_add(PUBLIC_CHANNEL_ID_MARGIN);
    if cursor < low || cursor >= high {
        low
    } else {
        cursor + 1
    }
}

/// Drop the oldest records from `gaps` until its length is at most `max`.
/// Pure so `record_chain_scan_gap`'s capping behavior is unit-testable
/// without a real `Storage`.
fn cap_gap_list(gaps: &mut Vec<GapRecord>, max: usize) {
    if gaps.len() > max {
        let drop = gaps.len() - max;
        gaps.drain(0..drop);
    }
}

/// Blocks past `cutoff_height` before the rollback checkpoint is GC'd.
/// Conservative — gives the operator time to inspect / notice any
/// issues before the safety net is removed. Spec 11-snapshot-sync.md §5a.6.
const SNAPSHOT_ROLLBACK_GC_BUFFER_BLOCKS: u64 = 100;

/// Garbage-collect the snapshot-bootstrap rollback directory if the
/// chain scanner has advanced safely past the apply cutoff.
///
/// Reads `SNAPSHOT_APPLIED_AT_HEIGHT` and `SNAPSHOT_ROLLBACK_DIR` from
/// `NODE_STATE`. If both are set AND `current_cursor >= applied_at
/// + SNAPSHOT_ROLLBACK_GC_BUFFER_BLOCKS`, deletes the rollback dir
/// from disk and clears both keys. Best-effort — any failure is
/// logged but does not propagate (the dir will just linger until
/// the next successful pass or until the operator deletes it).
pub fn gc_snapshot_rollback_if_ready(
    storage: &crate::storage::rocks::Storage,
    current_cursor: u64,
) {
    use crate::storage::schema::{cf, state_keys};

    let applied_at = match storage.get_cf(cf::NODE_STATE, state_keys::SNAPSHOT_APPLIED_AT_HEIGHT) {
        Ok(Some(b)) if b.len() == 8 => {
            u64::from_be_bytes(b.as_slice().try_into().unwrap())
        }
        _ => return, // no apply on record → nothing to GC
    };
    if current_cursor < applied_at + SNAPSHOT_ROLLBACK_GC_BUFFER_BLOCKS {
        return; // not safe yet — keep the rollback dir
    }

    let rollback_path_bytes = match storage.get_cf(cf::NODE_STATE, state_keys::SNAPSHOT_ROLLBACK_DIR) {
        Ok(Some(b)) if !b.is_empty() => b,
        _ => return, // no rollback dir recorded → nothing to delete
    };
    let path_str = match String::from_utf8(rollback_path_bytes) {
        Ok(s) => s,
        Err(_) => {
            warn!("SNAPSHOT_ROLLBACK_DIR not valid UTF-8 — clearing marker");
            let _ = storage.delete_cf(cf::NODE_STATE, state_keys::SNAPSHOT_ROLLBACK_DIR);
            return;
        }
    };
    let path = std::path::Path::new(&path_str);
    if path.exists() {
        // Hardening (audit Phase 3 Sec W4): refuse to GC if the recorded
        // path is a symlink — `remove_dir_all` follows symlinks and would
        // delete the target. Also require the path's canonical form to
        // sit beside an `ogmara-node` style data dir name (best-effort —
        // we don't have the data_dir handy here, so we only catch
        // symlinks and require an absolute path with our expected
        // `snapshot_rollback_` prefix in its file name).
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                warn!(rollback_dir = %path.display(), error = %e, "rollback GC: stat failed");
                return;
            }
        };
        if metadata.file_type().is_symlink() {
            warn!(
                rollback_dir = %path.display(),
                "Refusing to GC snapshot rollback dir — path is a symlink"
            );
            return;
        }
        let file_name_ok = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("snapshot_rollback_"))
            .unwrap_or(false);
        if !file_name_ok || !path.is_absolute() {
            warn!(
                rollback_dir = %path.display(),
                "Refusing to GC snapshot rollback dir — unexpected path shape"
            );
            return;
        }
        match std::fs::remove_dir_all(path) {
            Ok(_) => info!(
                rollback_dir = %path.display(),
                current_cursor,
                applied_at,
                "Snapshot rollback checkpoint garbage-collected (cursor advanced past cutoff)"
            ),
            Err(e) => {
                warn!(
                    rollback_dir = %path.display(),
                    error = %e,
                    "Failed to delete rollback dir during GC — will retry next scan tick"
                );
                return;
            }
        }
    }
    // Clear the marker keys so we don't repeat the work.
    let _ = storage.delete_cf(cf::NODE_STATE, state_keys::SNAPSHOT_ROLLBACK_DIR);
    let _ = storage.delete_cf(cf::NODE_STATE, state_keys::SNAPSHOT_APPLIED_AT_HEIGHT);
}

/// Merge `updates` into an existing `users` row, preserving every key the
/// caller does not explicitly set.
///
/// The `users` row is a free-form JSON document written by TWO owners: this
/// chain scanner (`registered_at`, `public_key`) and the message router
/// (`display_name`, `avatar_cid`, `bio`, `profile_updated_at`, and the bot
/// descriptor — spec 01 §3.11). Neither owner may round-trip it through a
/// closed typed struct: serde drops undeclared keys on re-serialize, so doing
/// that silently deletes the other owner's fields.
///
/// That is not hypothetical. `UserRegistered` and `PublicKeyUpdated` previously
/// went through `UserRecord`, whose six fields do not include
/// `profile_updated_at` — **the P-2 anti-replay watermark**. Every on-chain
/// registration, and every block re-scan, erased it. With the watermark gone
/// `prev_profile_ts` reads back as `0`, the LWW guard passes for any timestamp,
/// and a stale ProfileUpdate served over identity-sync (which deliberately skips
/// the clock-drift check) applies cleanly — exactly the backfill downgrade the
/// watermark exists to prevent.
///
/// Do NOT "fix" a future occurrence by adding fields to `UserRecord`. That
/// repairs today and breaks again the next time the router learns a key.
fn merge_user_fields(
    existing: &[u8],
    address: &str,
    updates: &[(&str, serde_json::Value)],
) -> serde_json::Value {
    // Parse failure yields `Null` rather than `{}` deliberately: an empty object
    // IS an object, so falling back to `{}` would skip the repair branch below
    // and silently drop `address` from a row rebuilt out of unparseable bytes.
    let mut record: serde_json::Value =
        serde_json::from_slice(existing).unwrap_or(serde_json::Value::Null);
    if !record.is_object() {
        // Unparseable, or valid JSON that is not an object (an array, a bare
        // string): start a fresh row rather than writing the malformed value
        // back and losing the update entirely.
        record = serde_json::json!({ "address": address });
    }
    if let serde_json::Value::Object(ref mut map) = record {
        for (k, v) in updates {
            map.insert((*k).to_string(), v.clone());
        }
    }
    record
}

#[cfg(test)]
mod user_record_merge_tests {
    use super::*;

    #[test]
    fn preserves_every_router_owned_key() {
        // REGRESSION: the scanner used to deserialize into `UserRecord` (six
        // fields) and re-serialize, silently deleting everything else — including
        // `profile_updated_at`, the anti-replay watermark, and the bot descriptor.
        let existing = serde_json::json!({
            "address": "klv1abc",
            "public_key": "old",
            "registered_at": 0,
            "display_name": "Chart Bot",
            "bio": "hi",
            "profile_updated_at": 1234567890u64,
            "is_bot": true,
            "bot_handle": "CoinTrendz",
            "bot_commands": [{"name": "c", "description": "Chart"}],
            "bot_updated_at": 1234567890u64,
        })
        .to_string();

        let merged = merge_user_fields(
            existing.as_bytes(),
            "klv1abc",
            &[
                ("public_key", serde_json::json!("new")),
                ("registered_at", serde_json::json!(999u64)),
            ],
        );

        // The on-chain fields were updated...
        assert_eq!(merged["public_key"], serde_json::json!("new"));
        assert_eq!(merged["registered_at"], serde_json::json!(999u64));
        // ...and every router-owned key survived.
        assert_eq!(merged["profile_updated_at"], serde_json::json!(1234567890u64));
        assert_eq!(merged["display_name"], serde_json::json!("Chart Bot"));
        assert_eq!(merged["bio"], serde_json::json!("hi"));
        assert_eq!(merged["is_bot"], serde_json::json!(true));
        assert_eq!(merged["bot_handle"], serde_json::json!("CoinTrendz"));
        assert_eq!(merged["bot_commands"][0]["name"], serde_json::json!("c"));
        assert_eq!(merged["bot_updated_at"], serde_json::json!(1234567890u64));
    }

    #[test]
    fn unknown_future_keys_survive_too() {
        // The point is the GENERAL property, not a list of today's field names:
        // a key this code has never heard of must still round-trip.
        let existing = serde_json::json!({ "address": "klv1x", "some_future_field": 42 }).to_string();
        let merged = merge_user_fields(
            existing.as_bytes(),
            "klv1x",
            &[("public_key", serde_json::json!("pk"))],
        );
        assert_eq!(merged["some_future_field"], serde_json::json!(42));
        assert_eq!(merged["public_key"], serde_json::json!("pk"));
    }

    #[test]
    fn a_malformed_row_does_not_swallow_the_update() {
        // Both arms behave identically here — the earlier inline versions did not.
        for bad in [b"not json".as_slice(), b"[1,2,3]".as_slice(), b"".as_slice()] {
            let merged =
                merge_user_fields(bad, "klv1y", &[("public_key", serde_json::json!("pk"))]);
            assert_eq!(merged["public_key"], serde_json::json!("pk"));
            assert_eq!(merged["address"], serde_json::json!("klv1y"));
        }
    }
}

#[cfg(test)]
mod range_position_tests {
    use super::*;

    // REGRESSION: the Klever testnet API silently ignores startBlock/endBlock
    // and just returns its most recent matching transactions regardless of
    // the requested range. Without this client-side classification, the
    // scanner reprocessed the same recent window of events on every tick
    // forever — the root cause of the l2-node 0.130.1/0.130.2 WAL
    // write-amplification investigation (which fixed the symptom via batch
    // size, not the actual cause).

    #[test]
    fn within_range_is_in_range() {
        assert_eq!(classify_block_range_position(50, 10, 100), RangePosition::InRange);
        // Inclusive at both boundaries.
        assert_eq!(classify_block_range_position(10, 10, 100), RangePosition::InRange);
        assert_eq!(classify_block_range_position(100, 10, 100), RangePosition::InRange);
    }

    #[test]
    fn newer_than_end_is_too_new() {
        assert_eq!(classify_block_range_position(101, 10, 100), RangePosition::TooNew);
        // The realistic shape of the bug: the API always hands back
        // current-tip transactions, far newer than an old target range.
        assert_eq!(
            classify_block_range_position(12_698_732, 1_000_000, 1_000_100),
            RangePosition::TooNew
        );
    }

    #[test]
    fn older_than_start_is_too_old() {
        assert_eq!(classify_block_range_position(9, 10, 100), RangePosition::TooOld);
        assert_eq!(classify_block_range_position(0, 10, 100), RangePosition::TooOld);
    }

    #[test]
    fn single_block_range_only_admits_that_block() {
        assert_eq!(classify_block_range_position(41, 42, 42), RangePosition::TooOld);
        assert_eq!(classify_block_range_position(42, 42, 42), RangePosition::InRange);
        assert_eq!(classify_block_range_position(43, 42, 42), RangePosition::TooNew);
    }
}

#[cfg(test)]
mod cap_outcome_tests {
    use super::*;

    // Audit 2026-09-28 (code review): the original fix used a bare
    // "was the target range ever reached" bool, which misclassified a range
    // reached with almost no budget left (e.g. page 48/50) as `Dense` —
    // subdividing it reproduces the ~400-call explosion this fix exists to
    // remove, since every sub-range shares the same tip-distance prefix and
    // hits the same cap. These tests pin the corrected boundary.

    #[test]
    fn never_reached_is_too_deep() {
        assert_eq!(classify_cap_outcome(None, 50), PageOutcome::CapExceededTooDeep);
    }

    #[test]
    fn reached_immediately_is_dense() {
        // Reached on page 1 of 50 — essentially the full budget remains.
        assert_eq!(classify_cap_outcome(Some(1), 50), PageOutcome::CapExceededDense);
    }

    #[test]
    fn reached_at_exact_half_budget_boundary_is_dense() {
        // 50 - 25 = 25 remaining, which is >= max_pages / 2 (25) — the
        // boundary is inclusive in favor of subdividing.
        assert_eq!(classify_cap_outcome(Some(25), 50), PageOutcome::CapExceededDense);
    }

    #[test]
    fn reached_just_past_half_budget_boundary_is_too_deep() {
        // 50 - 26 = 24 remaining, just under the threshold.
        assert_eq!(classify_cap_outcome(Some(26), 50), PageOutcome::CapExceededTooDeep);
    }

    #[test]
    fn reached_on_the_last_page_is_too_deep() {
        // The live symptom this test exists for: reached with essentially
        // zero budget left. Subdividing would just re-walk the same ~50
        // TooNew pages per half and hit the identical cap again.
        assert_eq!(classify_cap_outcome(Some(50), 50), PageOutcome::CapExceededTooDeep);
    }

    #[test]
    fn odd_max_pages_rounds_the_half_budget_down() {
        // max_pages/2 integer-divides: for 51, half-budget is 25, so
        // reaching it on page 26 leaves exactly 25 remaining — still dense.
        assert_eq!(classify_cap_outcome(Some(26), 51), PageOutcome::CapExceededDense);
        assert_eq!(classify_cap_outcome(Some(27), 51), PageOutcome::CapExceededTooDeep);
    }
}

#[cfg(test)]
mod channel_verification_tests {
    use super::*;

    // ── resolve_channel_type ────────────────────────────────────────

    #[test]
    fn resolve_channel_type_numeric() {
        assert_eq!(resolve_channel_type(&serde_json::json!({"channel_type": 0})), 0);
        assert_eq!(resolve_channel_type(&serde_json::json!({"channel_type": 1})), 1);
        assert_eq!(resolve_channel_type(&serde_json::json!({"channel_type": 2})), 2);
    }

    #[test]
    fn resolve_channel_type_legacy_string() {
        assert_eq!(resolve_channel_type(&serde_json::json!({"channel_type": "Public"})), 0);
        assert_eq!(resolve_channel_type(&serde_json::json!({"channel_type": "ReadPublic"})), 1);
        assert_eq!(resolve_channel_type(&serde_json::json!({"channel_type": "Private"})), 2);
    }

    #[test]
    fn resolve_channel_type_defaults_to_public_on_missing_or_malformed() {
        // Matches messages::router's existing convention (check_readonly_channel)
        // — defaulting to Public, not Private, is deliberate.
        assert_eq!(resolve_channel_type(&serde_json::json!({})), 0);
        assert_eq!(resolve_channel_type(&serde_json::json!({"channel_type": "garbage"})), 0);
        assert_eq!(resolve_channel_type(&serde_json::json!({"channel_type": null})), 0);
    }

    #[test]
    fn resolve_channel_type_does_not_truncate_large_values() {
        // Audit 2026-09-29 finding: the first attempt cast to `u8`, so a
        // malformed value like 258 silently became 2 (Private) instead of
        // falling back to the documented Public default. No cast now —
        // the u64 comparison in the caller decides eligibility correctly
        // regardless of how large a garbage value is.
        assert_eq!(resolve_channel_type(&serde_json::json!({"channel_type": 258})), 258);
        assert_ne!(resolve_channel_type(&serde_json::json!({"channel_type": 258})), 2);
    }

    // ── next_round_robin_id ──────────────────────────────────────────

    #[test]
    fn round_robin_advances_by_one_below_channel_count() {
        assert_eq!(next_round_robin_id(1, 10), 2);
        assert_eq!(next_round_robin_id(9, 10), 10);
    }

    #[test]
    fn round_robin_wraps_at_channel_count() {
        assert_eq!(next_round_robin_id(10, 10), 1);
    }

    #[test]
    fn round_robin_cursor_past_channel_count_also_wraps() {
        // Defensive case: channel_count shrinking is impossible on-chain,
        // but a persisted cursor from before some hypothetical future
        // change shouldn't get stuck past the current count.
        assert_eq!(next_round_robin_id(15, 10), 1);
    }

    #[test]
    fn round_robin_single_channel_always_returns_that_one_id() {
        assert_eq!(next_round_robin_id(0, 1), 1);
        assert_eq!(next_round_robin_id(1, 1), 1);
    }

    #[test]
    fn round_robin_zero_channels_returns_zero() {
        // Caller (sweep_channel_verification) is expected to check
        // `channel_count == 0` before ever calling this — pinned here as
        // a defined, non-panicking fallback rather than an invariant the
        // test suite silently assumes.
        assert_eq!(next_round_robin_id(0, 0), 0);
        assert_eq!(next_round_robin_id(5, 0), 0);
    }

    // ── cap_gap_list ─────────────────────────────────────────────────

    fn gap(n: u64) -> GapRecord {
        GapRecord { start: n, end: n, recorded_at: n }
    }

    #[test]
    fn cap_gap_list_no_op_under_the_limit() {
        let mut gaps = vec![gap(1), gap(2)];
        cap_gap_list(&mut gaps, 5);
        assert_eq!(gaps.len(), 2);
    }

    #[test]
    fn cap_gap_list_drops_oldest_first() {
        let mut gaps: Vec<_> = (1..=10u64).map(gap).collect();
        cap_gap_list(&mut gaps, 3);
        // Oldest (lowest recorded_at, front of the Vec) dropped — the most
        // recent 3 survive, in original order.
        assert_eq!(gaps.iter().map(|g| g.start).collect::<Vec<_>>(), vec![8, 9, 10]);
    }

    #[test]
    fn cap_gap_list_exact_boundary_is_no_op() {
        let mut gaps: Vec<_> = (1..=5u64).map(gap).collect();
        cap_gap_list(&mut gaps, 5);
        assert_eq!(gaps.len(), 5);
    }

    // ── ChannelVerificationState defaulting ─────────────────────────

    #[test]
    fn channel_verification_state_defaults_to_unverified() {
        // An empty/absent CHANNEL_VERIFICATION row (the common case — most
        // channels haven't been independently re-verified yet) must
        // deserialize to the SAFE value (unverified, not failed), never
        // silently treated as confirmed.
        let state: crate::chain::types::ChannelVerificationState =
            serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(state.creator_verified_at, None);
        assert!(!state.creator_verification_failed);
    }

    // ── partition_sweep_budget ───────────────────────────────────────
    // Round-4 finding: a shared budget drained in strict priority order
    // let one lane permanently starve every lane below it. Round-5
    // re-audit finding: the round-4 fix's own allocation could still
    // zero a lane at small-but-plausible configs (`total <= 3` zeroed
    // Lane 3 entirely). These pin the properties that actually close it.

    #[test]
    fn partition_never_exceeds_the_total() {
        for total in 0..=20usize {
            let (l1, l2, l3) = partition_sweep_budget(total);
            assert!(l1 + l2 + l3 <= total, "total={total} sum={}", l1 + l2 + l3);
        }
    }

    #[test]
    fn partition_at_default_budget_gives_every_lane_a_nonzero_share() {
        let (l1, l2, l3) = partition_sweep_budget(5);
        assert!(l1 >= 1 && l2 >= 1 && l3 >= 1);
        assert_eq!(l1 + l2 + l3, 5);
    }

    #[test]
    fn partition_gives_every_lane_a_nonzero_share_whenever_total_is_at_least_three() {
        // The property `config::validate`'s floor (3) exists to
        // guarantee — no deployed config should ever be able to reach a
        // total below this and still have `channel_verify.enabled`.
        for total in 3..=200usize {
            let (l1, l2, l3) = partition_sweep_budget(total);
            assert!(l1 >= 1 && l2 >= 1 && l3 >= 1, "total={total} got=({l1},{l2},{l3})");
        }
    }

    #[test]
    fn partition_at_below_floor_totals_does_not_panic_or_overflow() {
        // Below the config floor is unreachable via `config::validate`,
        // but the pure function itself must still degrade sanely rather
        // than panic — no fairness guarantee is claimed at this size.
        for total in 0..3usize {
            let (l1, l2, l3) = partition_sweep_budget(total);
            assert_eq!(l1 + l2 + l3, total);
        }
    }

    #[test]
    fn partition_zero_total_gives_every_lane_zero() {
        assert_eq!(partition_sweep_budget(0), (0, 0, 0));
    }

    // ── should_skip_no_backing_recheck ──────────────────────────────
    // Round-3.1 re-audit finding: Lane 2's fixed budget was dominated
    // forever by the same handful of standing negatives with no cooldown.

    #[test]
    fn no_cooldown_skip_when_last_outcome_was_not_a_failure() {
        let vstate = crate::chain::types::ChannelVerificationState {
            creator_verified_at: Some(100),
            creator_verification_failed: false,
            no_backing_checked_at: None,
        };
        assert!(!should_skip_no_backing_recheck(&vstate, 200));
    }

    #[test]
    fn cooldown_skips_a_recent_no_backing_result() {
        let vstate = crate::chain::types::ChannelVerificationState {
            creator_verified_at: None,
            creator_verification_failed: true,
            no_backing_checked_at: Some(1_000),
        };
        assert!(should_skip_no_backing_recheck(
            &vstate,
            1_000 + NO_BACKING_RECHECK_COOLDOWN_SECS - 1
        ));
    }

    #[test]
    fn cooldown_expires_and_allows_a_recheck() {
        let vstate = crate::chain::types::ChannelVerificationState {
            creator_verified_at: None,
            creator_verification_failed: true,
            no_backing_checked_at: Some(1_000),
        };
        assert!(!should_skip_no_backing_recheck(
            &vstate,
            1_000 + NO_BACKING_RECHECK_COOLDOWN_SECS
        ));
    }

    #[test]
    fn failed_but_never_timestamped_never_skips() {
        // Defensive: a failed flag with no timestamp (shouldn't happen via
        // `apply_channel_verification_result`, which always stamps both
        // together, but a pre-round-3.1 persisted row would look like
        // this) must not skip forever with no way to expire.
        let vstate = crate::chain::types::ChannelVerificationState {
            creator_verified_at: None,
            creator_verification_failed: true,
            no_backing_checked_at: None,
        };
        assert!(!should_skip_no_backing_recheck(&vstate, 1_000_000));
    }

    // ── next_out_of_range_id (Lane 2's bounded rotation, round 5) ────
    // Round-4/round-5 re-audit finding: an unbounded out-of-range
    // candidate set let a handful of cheap padding rows permanently
    // starve anything planted beyond them, twice, in two different ways.
    // The fix bounds the SET (via `PUBLIC_CHANNEL_ID_MARGIN`, enforced at
    // ingestion) and rotates through it exactly like Lane 3 already does
    // over `1..=channel_count` — these tests pin the rotation itself.

    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    #[test]
    fn out_of_range_rotation_starts_at_the_frontier() {
        assert_eq!(next_out_of_range_id(0, 100), 101);
    }

    #[test]
    fn out_of_range_rotation_advances_by_one_within_the_window() {
        assert_eq!(next_out_of_range_id(101, 100), 102);
    }

    #[test]
    fn out_of_range_rotation_wraps_at_the_margin() {
        let high = 100 + PUBLIC_CHANNEL_ID_MARGIN;
        assert_eq!(next_out_of_range_id(high, 100), 101);
    }

    #[test]
    fn out_of_range_rotation_snaps_forward_when_frontier_has_advanced_past_it() {
        // The persisted cursor can fall BELOW the current frontier if
        // channel_count grew since the last tick (the id it pointed to is
        // now Lane 1/Lane 3's job, not this lane's) — must snap into the
        // window, not treat the stale value as still valid.
        assert_eq!(next_out_of_range_id(50, 100), 101);
    }

    #[test]
    fn out_of_range_window_can_never_exceed_the_margin() {
        // The whole point: no matter how many ticks run, the rotation
        // never visits more than PUBLIC_CHANNEL_ID_MARGIN distinct ids
        // for a fixed channel_count — there is no id it can permanently
        // miss within that bound.
        let mut cursor = 0u64;
        let mut visited = std::collections::HashSet::new();
        for _ in 0..(PUBLIC_CHANNEL_ID_MARGIN * 3) {
            cursor = next_out_of_range_id(cursor, 100);
            visited.insert(cursor);
        }
        assert_eq!(visited.len() as u64, PUBLIC_CHANNEL_ID_MARGIN);
        assert!(visited.iter().all(|&id| id > 100 && id <= 100 + PUBLIC_CHANNEL_ID_MARGIN));
    }

    // ── merge_channel_created_into_existing (round 7) ────────────────
    // Round-7 re-audit finding: the round-6 fix protected `channel_type`
    // in this branch but left `creator`/`slug`/`created_at` unconditional
    // for a currently-Private row — the identical self-label-collision
    // class this feature closes elsewhere. These pin the fixed behavior.

    #[test]
    fn merge_corrects_creator_but_never_touches_channel_type_when_not_private() {
        let mut meta = serde_json::json!({
            "creator": "klv1squatter",
            "channel_type": 1, // ReadPublic — L2-flipped since creation
            "created_at": 0,
        });
        let outcome = merge_channel_created_into_existing(
            &mut meta,
            42,
            "real-slug",
            "klv1real",
            5_000,
        );
        assert_eq!(outcome, ChannelFieldMergeOutcome::Merged);
        assert_eq!(meta["creator"], serde_json::json!("klv1real"));
        assert_eq!(meta["slug"], serde_json::json!("real-slug"));
        assert_eq!(meta["created_at"], serde_json::json!(5_000));
        // Never touched — L2-authoritative, must survive every re-scan.
        assert_eq!(meta["channel_type"], serde_json::json!(1));
    }

    #[test]
    fn merge_detects_but_never_touches_a_currently_private_row() {
        let mut meta = serde_json::json!({
            "creator": "klv1legacy_owner",
            "slug": "my-old-private-channel",
            "channel_type": 2, // Private
            "created_at": 111,
            "display_name": "Legacy Channel",
        });
        let before = meta.clone();
        let outcome = merge_channel_created_into_existing(
            &mut meta,
            7,
            "unrelated-onchain-slug",
            "klv1unrelated_onchain_creator",
            999_999,
        );
        assert_eq!(outcome, ChannelFieldMergeOutcome::PrivateCollisionDetected);
        // Completely untouched — not just channel_type, but creator,
        // slug, created_at, and any other existing field too.
        assert_eq!(meta, before);
    }

    #[test]
    fn merge_reports_not_an_object_without_mutating() {
        let mut meta = serde_json::json!("not an object");
        let outcome = merge_channel_created_into_existing(&mut meta, 1, "s", "klv1x", 0);
        assert_eq!(outcome, ChannelFieldMergeOutcome::NotAnObject);
        assert_eq!(meta, serde_json::json!("not an object"));
    }

    #[test]
    fn merge_defaults_missing_l2_only_fields_without_overwriting_present_ones() {
        let mut meta = serde_json::json!({
            "creator": "klv1old",
            "channel_type": 0,
            "created_at": 0,
            "display_name": "Kept As-Is",
        });
        let outcome = merge_channel_created_into_existing(&mut meta, 1, "s", "klv1new", 100);
        assert_eq!(outcome, ChannelFieldMergeOutcome::Merged);
        assert_eq!(meta["display_name"], serde_json::json!("Kept As-Is"));
        assert_eq!(meta["description"], serde_json::Value::Null);
        assert_eq!(meta["member_count"], serde_json::json!(0));
    }

    // ── apply_channel_transfer_to_existing (round 9) ─────────────────
    // Round-9 code audit finding (CRITICAL, pre-existing): this handler
    // unconditionally overwrote `creator` on ChannelTransferred with no
    // currently-Private guard at all — the exact sibling-handler version
    // of the bug round 6/7 already fixed for ChannelCreated's merge, and
    // round 8's own bug for apply_channel_verification_result's Confirmed
    // arm. `is_channel_creator` gates delete/ban/update/invite purely on
    // `creator`, so this let anyone controlling a colliding on-chain
    // transfer silently seize admin rights over an unrelated real
    // private channel.

    #[test]
    fn transfer_updates_creator_when_not_private() {
        let mut meta = serde_json::json!({
            "creator": "klv1old",
            "channel_type": 0,
        });
        let outcome = apply_channel_transfer_to_existing(&mut meta, "klv1new");
        assert_eq!(outcome, ChannelFieldMergeOutcome::Merged);
        assert_eq!(meta["creator"], serde_json::json!("klv1new"));
    }

    #[test]
    fn transfer_detects_but_never_touches_a_currently_private_row() {
        let mut meta = serde_json::json!({
            "creator": "klv1legacy_owner",
            "channel_type": 2, // Private
            "display_name": "Legacy Channel",
        });
        let before = meta.clone();
        let outcome = apply_channel_transfer_to_existing(&mut meta, "klv1attacker_controlled");
        assert_eq!(outcome, ChannelFieldMergeOutcome::PrivateCollisionDetected);
        assert_eq!(meta, before);
    }

    #[test]
    fn transfer_reports_not_an_object_without_mutating() {
        let mut meta = serde_json::json!("not an object");
        let outcome = apply_channel_transfer_to_existing(&mut meta, "klv1new");
        assert_eq!(outcome, ChannelFieldMergeOutcome::NotAnObject);
        assert_eq!(meta, serde_json::json!("not an object"));
    }

    // ── should_skip_recent_positive_reverify (round 5, S4) ───────────

    #[test]
    fn never_verified_row_is_never_skipped() {
        let vstate = crate::chain::types::ChannelVerificationState::default();
        assert!(!should_skip_recent_positive_reverify(&vstate, 1_000_000));
    }

    #[test]
    fn recently_confirmed_row_is_skipped() {
        let vstate = crate::chain::types::ChannelVerificationState {
            creator_verified_at: Some(1_000),
            creator_verification_failed: false,
            no_backing_checked_at: None,
        };
        assert!(should_skip_recent_positive_reverify(
            &vstate,
            1_000 + POSITIVE_REVERIFY_COOLDOWN_SECS - 1
        ));
    }

    #[test]
    fn stale_confirmation_is_not_skipped() {
        let vstate = crate::chain::types::ChannelVerificationState {
            creator_verified_at: Some(1_000),
            creator_verification_failed: false,
            no_backing_checked_at: None,
        };
        assert!(!should_skip_recent_positive_reverify(
            &vstate,
            1_000 + POSITIVE_REVERIFY_COOLDOWN_SECS
        ));
    }

    #[test]
    fn a_standing_negative_is_not_governed_by_the_positive_cooldown() {
        // `creator_verification_failed` rows are `should_skip_no_backing_
        // recheck`'s concern, not this one's — even with a (stale, from
        // before the flip) `creator_verified_at`, this must return false
        // so the OTHER cooldown gets to make the actual decision.
        let vstate = crate::chain::types::ChannelVerificationState {
            creator_verified_at: Some(1_000),
            creator_verification_failed: true,
            no_backing_checked_at: Some(5_000),
        };
        assert!(!should_skip_recent_positive_reverify(&vstate, 5_001));
    }

    // ── apply_channel_verification_result invariants ────────────────
    // Round-3.1 re-audit finding: the exact assertions round 2 got wrong
    // (Confirmed silently overwriting channel_type; a stale pre-await
    // read deciding whether a row is "currently Private") had zero direct
    // test coverage — pinned here against the real write path.

    fn seed_channel(storage: &Storage, id: u64, creator: &str, channel_type: u8) {
        let row = serde_json::json!({
            "creator": creator,
            "channel_type": channel_type,
            "created_at": 0,
        });
        storage
            .put_cf(cf::CHANNELS, &id.to_be_bytes(), &serde_json::to_vec(&row).unwrap())
            .unwrap();
    }

    fn read_channel(storage: &Storage, id: u64) -> serde_json::Value {
        let bytes = storage.get_cf(cf::CHANNELS, &id.to_be_bytes()).unwrap().unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn confirmed_outcome_never_touches_channel_type_even_when_it_diverges() {
        // The L2 layer is authoritative for Public<->ReadPublic (a
        // ChannelUpdate-driven flip is EXPECTED to diverge from the
        // immutable on-chain snapshot) — Confirmed must never resync it,
        // even though the stored type here (ReadPublic) differs from
        // nothing in this test on purpose: this pins that Confirmed
        // simply never writes the field at all.
        let (storage, _dir) = db();
        seed_channel(&storage, 42, "klv1creator", 1); // ReadPublic
        storage
            .apply_channel_verification_result(
                42,
                crate::storage::rocks::ChannelVerificationOutcome::Confirmed,
                1_000,
            )
            .unwrap();
        let row = read_channel(&storage, 42);
        assert_eq!(row["channel_type"], serde_json::json!(1));
        assert_eq!(row["creator"], serde_json::json!("klv1creator"));
    }

    #[test]
    fn confirmed_outcome_on_a_currently_private_row_is_also_a_detected_collision() {
        // Round 8, CRITICAL (security audit): the caller picks
        // `Confirmed` purely from `verified_creator == stored_creator`,
        // BEFORE any Private check — so a currently-Private row whose
        // stored creator happens to MATCH the SC's real creator for that
        // id reached `Confirmed` with no guard at all, unlike `Corrected`.
        // That match is trivial for a deliberate attacker to arrange
        // (sign both the local Private create and the real on-chain
        // create with the same wallet) — it's the ONLY way to dodge
        // `Corrected`'s detection. Any on-chain backing for a
        // claimed-Private id is anomalous regardless of whether the
        // creator matches: `Confirmed` must detect-and-not-stamp here
        // exactly like `Corrected` does.
        let (storage, _dir) = db();
        seed_channel(&storage, 9, "klv1attacker", 2); // Private
        let detected = storage
            .apply_channel_verification_result(
                9,
                crate::storage::rocks::ChannelVerificationOutcome::Confirmed,
                1_000,
            )
            .unwrap();
        assert!(detected);
        let row = read_channel(&storage, 9);
        assert_eq!(row["channel_type"], serde_json::json!(2));
        assert_eq!(row["creator"], serde_json::json!("klv1attacker"));
        let vstate = storage.read_channel_verification_state(9);
        assert_eq!(vstate.creator_verified_at, None);
        assert!(!vstate.creator_verification_failed);
    }

    #[test]
    fn corrected_outcome_detects_but_never_touches_a_currently_private_row() {
        // Round 6, security finding S4: auto-converting a currently-
        // Private row's creator/type on a `Corrected` outcome used to be
        // "correct" (closing the self-label-to-dodge-verification
        // bypass) — but `PRIVATE_CHANNEL_ID_FLOOR` now closes that bypass
        // at ingestion, so the only rows left reaching this path are
        // pre-floor legacy rows this sweep can no longer distinguish
        // from a genuinely legitimate private channel. The row must be
        // left COMPLETELY untouched, and the function must report the
        // detection via its return value (`true`) so the caller can
        // alert instead of silently correcting.
        let (storage, _dir) = db();
        seed_channel(&storage, 7, "klv1squatter", 2); // Private
        let detected = storage
            .apply_channel_verification_result(
                7,
                crate::storage::rocks::ChannelVerificationOutcome::Corrected {
                    verified_creator: "klv1real".to_string(),
                },
                1_000,
            )
            .unwrap();
        assert!(detected);
        let row_a = read_channel(&storage, 7);
        assert_eq!(row_a["channel_type"], serde_json::json!(2));
        assert_eq!(row_a["creator"], serde_json::json!("klv1squatter"));
        // Round 7 (security audit finding): a detected-but-uncorrected
        // collision must NOT stamp creator_verified_at — doing so arms
        // `should_skip_recent_positive_reverify`'s 24h cooldown on the
        // exact row that most needs to keep being re-checked and
        // re-alerted on every future lane pass.
        let vstate_a = storage.read_channel_verification_state(7);
        assert_eq!(vstate_a.creator_verified_at, None);
        assert!(!vstate_a.creator_verification_failed);

        // Case B: currently ReadPublic (NOT Private) -> creator IS
        // corrected as before, the function reports no detection, and
        // THIS genuinely-resolved case DOES stamp creator_verified_at.
        seed_channel(&storage, 8, "klv1squatter", 1); // ReadPublic
        let detected = storage
            .apply_channel_verification_result(
                8,
                crate::storage::rocks::ChannelVerificationOutcome::Corrected {
                    verified_creator: "klv1real".to_string(),
                },
                1_000,
            )
            .unwrap();
        assert!(!detected);
        let row_b = read_channel(&storage, 8);
        assert_eq!(row_b["channel_type"], serde_json::json!(1));
        assert_eq!(row_b["creator"], serde_json::json!("klv1real"));
        let vstate_b = storage.read_channel_verification_state(8);
        assert_eq!(vstate_b.creator_verified_at, Some(1_000));
    }

    #[test]
    fn no_on_chain_backing_leaves_channels_row_untouched_and_stamps_cooldown() {
        let (storage, _dir) = db();
        seed_channel(&storage, 100, "klv1attacker", 0); // Public
        storage
            .apply_channel_verification_result(
                100,
                crate::storage::rocks::ChannelVerificationOutcome::NoOnChainBacking,
                5_000,
            )
            .unwrap();
        let row = read_channel(&storage, 100);
        assert_eq!(row["creator"], serde_json::json!("klv1attacker"));
        let vstate = storage.read_channel_verification_state(100);
        assert!(vstate.creator_verification_failed);
        assert_eq!(vstate.no_backing_checked_at, Some(5_000));
    }

    #[test]
    fn tombstoned_channel_is_skipped_even_with_a_pending_correction() {
        // Fresh-read-under-the-lock guard: a legitimate delete landing
        // between the throttled SC call returning and this write must
        // win — no resurrection. Round-4 code audit finding: the
        // original version of this test seeded the row BEFORE
        // tombstoning, so `tombstone_channel` itself already deletes the
        // CHANNELS row in the same write batch — the assertion passed
        // even with the guard commented out, since there was nothing
        // left to resurrect either way. Seeding AFTER the tombstone
        // (simulating the exact race: a delete landing while a
        // correction is in flight, so by the time the correction is
        // ready to write, a NEW row already exists alongside the
        // tombstone) and asserting the row is UNCHANGED — not corrected
        // to `verified_creator` — actually exercises the guard.
        let (storage, _dir) = db();
        storage.tombstone_channel(55, 0, None).unwrap();
        seed_channel(&storage, 55, "klv1squatter", 0);
        storage
            .apply_channel_verification_result(
                55,
                crate::storage::rocks::ChannelVerificationOutcome::Corrected {
                    verified_creator: "klv1real".to_string(),
                },
                1_000,
            )
            .unwrap();
        let row = read_channel(&storage, 55);
        assert_eq!(row["creator"], serde_json::json!("klv1squatter"));
        let vstate = storage.read_channel_verification_state(55);
        assert_eq!(vstate.creator_verified_at, None);
    }
}
