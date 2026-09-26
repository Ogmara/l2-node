//! `[governance] auto_execute` background task (l2-node 0.134.0).
//!
//! Auto-executes THIS node's own node-track governance proposals once
//! their voting period ends and the tally passes (quorum + supermajority
//! met) — closing the gap where `executeNodeProposal` is on-chain
//! permissionless (see `smart-contract/src/node_governance.rs`) but
//! nothing was actually calling it, leaving passed proposals stuck
//! showing `closed` ("awaiting someone to click Execute",
//! `crate::api::admin::proposal_status`) until an operator noticed and
//! clicked the dashboard button.
//!
//! **Scope is deliberately narrow**: a node only ever auto-executes
//! proposals IT created (`proposer == this node's anchor wallet
//! address`) — never another node's.
//!
//! **Discovery is a persisted, incremental cursor, not a full rescan.**
//! A naive "paginate `listNodeProposals` from 0 every tick and filter"
//! design re-fetches the ENTIRE network-wide proposal history on every
//! tick forever (Code Audit finding, l2-node 0.134.0 fix pass) — cost
//! that grows without bound as the network accumulates proposals, none
//! of which are ever pruned on-chain. Instead this task persists
//! `LAST_SCANNED_TOTAL_KEY` (how far the one-time discovery scan has
//! gotten) and `TRACKED_IDS_KEY` (the small set of this node's own
//! not-yet-terminal proposal ids found so far). Each tick: (1) scan only
//! the NEW range `[last_scanned_total, current_total)` for proposals
//! this node created, extending the tracked set; (2) re-fetch CURRENT
//! status for just the tracked ids (one direct `listNodeProposals(offset
//! = id - 1, limit = 1)` call per id — ids are dense/1-based/never
//! cleared, see `smart-contract`'s `list_node_proposals`, so this always
//! addresses exactly proposal `id`). Both steps cost O(new proposals
//! since last tick) + O(this node's own open proposals), never O(total
//! network history). A proposal drops out of the tracked set the moment
//! it's observed `executed` or genuinely `failed` (SC-level tally can
//! never pass) — see `maybe_execute`.
//!
//! **No new signing path.** Reuses the exact same `governance_submit`
//! channel (`AppState`'s HTTP "Execute" button sends through it too,
//! handled by `StateAnchorer::handle_gov`) — the anchoring task keeps
//! sole custody of the signing key; this task only holds a clone of the
//! `mpsc::Sender`.
//!
//! **Backoff, not a mass-retry loop.** Per-proposal state (just
//! `next_attempt_at`) lives in the `NODE_STATE` RocksDB column family,
//! same idiom as `LAST_ANCHOR_TS`. On a submit failure classified as
//! "insufficient balance" (Klever's TX-broadcast errors carry no
//! structured code, so this uses the same substring heuristic already
//! used client-side for the identical purpose in
//! `desktop/src/lib/klever.ts` and `web/src/lib/klever.ts`), the task
//! backs off to `funds_retry_interval_secs` instead of retrying every
//! `check_interval_secs` tick, and fires
//! `AlertType::GovernanceProposalExecuteFundsBlocked`. That alert is
//! fired on every such attempt (not gated by a persisted "already
//! notified" flag) — deduplication across time is left entirely to
//! `AlertEngine`'s own per-`AlertType` cooldown, the SAME pattern
//! `metadata_reconcile.rs` already relies on for `MetadataDriftDetected`
//! ("cooldown bounds re-fire ... even though the timer cadence is ...
//! too"). An earlier draft added a second, persistent per-proposal
//! `notified` latch on top of that; a Code Audit pass found it could
//! permanently suppress a genuinely-new proposal's first alert if an
//! unrelated proposal's cooldown window happened to overlap it — the
//! fix is to not duplicate the engine's own dedup logic, not to make the
//! duplicate more clever. Unclassified failures (e.g. a stale-read race
//! on quorum, or node/chain clock skew making this task see `closed`
//! before the chain's own block-timestamp-gated `require!` agrees) get a
//! shorter [`UNKNOWN_ERROR_RETRY_INTERVAL`] backoff with no alert, so a
//! transient disagreement logs and retries at a bounded rate rather than
//! warning on every tick forever.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::api::admin::{encode_u64_calldata_arg, proposal_status};
use crate::chain::anchoring::GovernanceSubmitRequest;
use crate::chain::sc_views::{self, ProposalSummary};
use crate::notifications::alerts::{AlertEvent, AlertEventSender, AlertType};
use crate::storage::rocks::Storage;
use crate::storage::schema::cf;

/// Grace period before the first check tick — same reasoning as
/// `metadata_reconcile::STARTUP_GRACE`: give a freshly started node
/// time to settle (and its anchoring task time to come up) before
/// hitting the SC view.
const STARTUP_GRACE: Duration = Duration::from_secs(60);

/// Page size for the discovery scan's `listNodeProposals` calls. MUST
/// stay `<= smart-contract::governance::LIST_PROPOSALS_MAX_LIMIT` (20).
/// A prior draft set this to 40 to match `sc_views::MAX_RETURNED_PROPOSAL_ROWS`
/// (a CONSUMER-side defensive ceiling on an oversized response, not a
/// request limit) — every request then hit the SC's own
/// `require!(limit <= LIST_PROPOSALS_MAX_LIMIT)`, which
/// `list_proposals_generic` treats as a benign "no rows" empty result
/// (`resp.is_require_failure()` → `Ok(Vec::new())`), not an error. The
/// task ran forever, found nothing, and logged nothing — a Code Audit
/// pass caught the silent no-op. Do not raise this without also raising
/// the SC's own limit.
const PAGE_SIZE: u32 = 20;

/// Defense-in-depth cap on how many pages ONE discovery scan will walk
/// in a single tick. In steady state the scanned range
/// `[last_scanned_total, current_total)` is tiny (this node's own
/// proposals are rare, deliberate, multi-day-voting-period actions), so
/// this cap only matters if the network-wide proposal count jumps by a
/// large amount between ticks. When hit, the scan stops partway and
/// resumes from exactly where it left off next tick (see
/// `discover_new_own_proposals`) — no proposal is silently skipped.
const MAX_DISCOVERY_PAGES_PER_TICK: u32 = 250;

/// Backoff applied to a submit failure that isn't classified as either
/// "insufficient funds" or "already executed" — e.g. a stale-read race,
/// or node/chain clock skew (this task's `proposal_status` uses the
/// node's wall clock; the SC gates on `get_block_timestamp()`). Shorter
/// than `funds_retry_interval_secs` since these are expected to be
/// transient, but still bounded so a permanently-unexecutable edge case
/// (e.g. a future contract upgrade narrowing a param's valid range out
/// from under an already-passed proposal) logs at a fixed rate rather
/// than every `check_interval_secs` tick forever.
const UNKNOWN_ERROR_RETRY_INTERVAL: Duration = Duration::from_secs(3600);

/// Key prefix for per-proposal backoff bookkeeping in `cf::NODE_STATE`.
/// Full key = prefix ++ `proposal_id.to_be_bytes()`.
const BACKOFF_KEY_PREFIX: &[u8] = b"gov_autoexec:backoff:";

/// Single key holding the persisted set of this node's own tracked
/// (not-yet-terminal) proposal ids — see module doc "Discovery is a
/// persisted, incremental cursor". Value is a flat concatenation of
/// 8-byte big-endian ids, sorted ascending, deduplicated.
const TRACKED_IDS_KEY: &[u8] = b"gov_autoexec:tracked_ids";

/// Single key holding how far the one-time discovery scan has gotten —
/// `getNodeProposalCount()` as of the last tick that fully completed its
/// scan of `[old value, new value)`. 8-byte big-endian `u64`.
const LAST_SCANNED_TOTAL_KEY: &[u8] = b"gov_autoexec:last_scanned_total";

fn backoff_key(proposal_id: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(BACKOFF_KEY_PREFIX.len() + 8);
    k.extend_from_slice(BACKOFF_KEY_PREFIX);
    k.extend_from_slice(&proposal_id.to_be_bytes());
    k
}

/// Persisted per-proposal backoff state — just the next-attempt time.
/// 8 bytes, big-endian.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct BackoffState {
    /// Unix seconds; don't attempt again before this.
    next_attempt_at: u64,
}

impl BackoffState {
    fn encode(&self) -> [u8; 8] {
        self.next_attempt_at.to_be_bytes()
    }

    fn decode(bytes: &[u8]) -> Self {
        if bytes.len() < 8 {
            return Self::default();
        }
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[0..8]);
        Self {
            next_attempt_at: u64::from_be_bytes(ts),
        }
    }
}

/// Classify a stringified submit error as "insufficient balance to pay
/// the transaction fee". Klever TX-broadcast/simulation errors carry no
/// structured error code (see `anchoring.rs::simulation_error`) — this
/// mirrors the exact substring heuristic already used client-side for
/// the same classification in `desktop/src/lib/klever.ts` and
/// `web/src/lib/klever.ts`.
fn is_insufficient_funds_error(err: &str) -> bool {
    let lower = err.to_lowercase();
    lower.contains("insufficient") || lower.contains("balance") || lower.contains("not enough")
}

/// True when the SC rejected the call because someone else (e.g. a
/// manual dashboard click) already executed this proposal — a benign
/// race, not a failure to react to.
fn is_already_executed_error(err: &str) -> bool {
    err.to_lowercase().contains("already executed")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn encode_ids(ids: &[u64]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ids.len() * 8);
    for id in ids {
        buf.extend_from_slice(&id.to_be_bytes());
    }
    buf
}

fn decode_ids(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|c| u64::from_be_bytes(c.try_into().expect("chunks_exact(8) guarantees exact length")))
        .collect()
}

/// The auto-executor task. One per node when `[anchoring] enabled` and
/// `[governance] auto_execute` are both true at startup.
pub struct GovernanceAutoExecutor {
    http: reqwest::Client,
    klever_node_url: String,
    contract_address: String,
    /// The anchor wallet address — proposals with a different
    /// `proposer` are never touched (see module doc, "Scope").
    ///
    /// **Known limitation (re-audit finding N9, not fixed):** the
    /// discovery cursor (`LAST_SCANNED_TOTAL_KEY`) is not keyed by this
    /// address. If `[anchoring] wallet_key` is rotated to a PREVIOUSLY
    /// used address that proposed something before this node's cursor
    /// had advanced past it, that old proposal will not be (re)discovered
    /// — the range it's in was already marked scanned under the old
    /// wallet's filter. Rotating to a wallet address that has never
    /// proposed anything is unaffected. Considered too narrow an edge
    /// case (deliberately restoring an old anchor key with unexecuted
    /// proposals under it) to justify a per-wallet cursor for now.
    wallet_address: String,
    storage: Storage,
    governance_submit: mpsc::Sender<GovernanceSubmitRequest>,
    alert_event_tx: Option<AlertEventSender>,
    check_interval: Duration,
    funds_retry_interval: Duration,
}

impl GovernanceAutoExecutor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        klever_node_url: String,
        contract_address: String,
        wallet_address: String,
        storage: Storage,
        governance_submit: mpsc::Sender<GovernanceSubmitRequest>,
        alert_event_tx: Option<AlertEventSender>,
        check_interval: Duration,
        funds_retry_interval: Duration,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            http,
            klever_node_url,
            contract_address,
            wallet_address,
            storage,
            governance_submit,
            alert_event_tx,
            check_interval,
            funds_retry_interval,
        })
    }

    /// Run the auto-executor loop until shutdown. First check fires
    /// after `STARTUP_GRACE`; subsequent ones every `check_interval`.
    ///
    /// `check_interval` and `funds_retry_interval` are validated `> 0`
    /// by `Config::validate()` at startup (`tokio::time::interval`
    /// panics on a zero duration) — this task trusts that invariant
    /// rather than re-checking it.
    pub async fn run(mut self, mut shutdown_rx: broadcast::Receiver<()>) {
        if self.klever_node_url.is_empty() || self.contract_address.is_empty() {
            warn!("governance_autoexec: klever_node_url or contract_address not set; disabled");
            let _ = shutdown_rx.recv().await;
            return;
        }
        if self.wallet_address.is_empty() {
            warn!(
                "governance_autoexec: wallet_address is empty; cannot identify own proposals, exiting"
            );
            let _ = shutdown_rx.recv().await;
            return;
        }

        info!(
            contract = %self.contract_address,
            check_interval_secs = self.check_interval.as_secs(),
            funds_retry_interval_secs = self.funds_retry_interval.as_secs(),
            "governance_autoexec started"
        );

        tokio::select! {
            _ = tokio::time::sleep(STARTUP_GRACE) => {}
            _ = shutdown_rx.recv() => {
                debug!("governance_autoexec shutting down during startup grace");
                return;
            }
        }

        let mut interval = tokio::time::interval(self.check_interval);
        // Security Audit finding, l2-node 0.134.0: the default
        // `MissedTickBehavior::Burst` would replay every missed tick
        // back-to-back the moment a slow tick returns (e.g. the initial
        // discovery catch-up on a node started long after this feature
        // shipped, walking a large pre-existing proposal history in
        // `MAX_DISCOVERY_PAGES_PER_TICK`-sized bites across several
        // ticks) — hammering the configured Klever RPC endpoint
        // continuously instead of resuming at the configured cadence.
        // `Delay` just resumes the normal interval from whenever the
        // slow tick finished.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.tick_once().await;
                }
                _ = shutdown_rx.recv() => {
                    debug!("governance_autoexec shutting down");
                    break;
                }
            }
        }
    }

    /// One reconcile pass — public so tests can force a tick.
    pub async fn tick_once(&mut self) {
        let now = now_unix();

        match self.discover_new_own_proposals().await {
            Ok((new_ids, new_last_scanned)) => {
                // Re-audit finding N3 (l2-node 0.134.0): persist newly
                // discovered ids BEFORE advancing the scan cursor past
                // them, not after. `discover_new_own_proposals` no
                // longer writes the cursor itself — it only computes how
                // far it got — specifically so this ordering can be
                // enforced here. A crash or write failure between these
                // two calls now costs at most a harmless re-scan of the
                // same range next tick; the old order could permanently
                // lose a proposal (cursor advanced, ids never saved).
                if !new_ids.is_empty() {
                    let mut tracked = self.load_tracked_ids();
                    let before = tracked.len();
                    for id in new_ids {
                        if !tracked.contains(&id) {
                            tracked.push(id);
                        }
                    }
                    if tracked.len() != before {
                        tracked.sort_unstable();
                        self.save_tracked_ids(&tracked);
                    }
                }
                self.write_last_scanned_total(new_last_scanned);
            }
            Err(e) => {
                debug!(error = %e, "governance_autoexec: discovery scan failed; will retry next tick");
            }
        }

        let tracked = self.load_tracked_ids();
        if tracked.is_empty() {
            return;
        }

        let proposals = self.fetch_tracked_proposals(&tracked).await;
        let mut still_tracked = tracked.clone();
        for p in &proposals {
            if self.maybe_execute(p, now).await {
                still_tracked.retain(|&id| id != p.id);
            }
        }
        if still_tracked.len() != tracked.len() {
            self.save_tracked_ids(&still_tracked);
        }
    }

    /// Scan the NEW proposal-id range since the last completed scan for
    /// proposals this node created. Returns their ids (callers merge
    /// into the persisted tracked set). Advances `LAST_SCANNED_TOTAL_KEY`
    /// to exactly how far this call actually got — `current_total` on a
    /// full pass, or the partial offset reached if
    /// `MAX_DISCOVERY_PAGES_PER_TICK` cut it short — so a later tick
    /// resumes precisely, never skipping or re-scanning the same range
    /// twice. Returns `(new_ids, new_last_scanned)`; the CALLER persists
    /// both (ids first, cursor second — see `tick_once`'s N3 comment),
    /// this function does not write any state itself.
    ///
    /// **Does NOT break early on an empty page** (re-audit finding N2,
    /// l2-node 0.134.0): an earlier version treated `page.is_empty()` as
    /// "reached the end" and advanced the cursor straight to `total`,
    /// skipping whatever lay beyond that page — but `offset < total`
    /// already guarantees the SC has real rows there, so an empty
    /// response now means either (a) `sc_views::list_proposals_generic`'s
    /// lenient per-row decoding (added in the SAME fix pass, see its own
    /// doc) skipped every row in that page because all of them had an
    /// undecodable field, or (b) a transient benign-empty response. Both
    /// are reasons to log and MOVE ON to the next page, never reasons to
    /// stop scanning — stopping would silently and permanently drop this
    /// node's own proposals if they happen to land past a page of
    /// hostile/malformed proposals from other addresses, recreating the
    /// exact "feature silently does nothing" failure class the
    /// `PAGE_SIZE` bug caused. The loop's only real exit conditions are
    /// therefore `offset >= total` (genuinely caught up) and the
    /// `MAX_DISCOVERY_PAGES_PER_TICK` safety cap.
    async fn discover_new_own_proposals(&self) -> anyhow::Result<(Vec<u64>, u64)> {
        let total = sc_views::get_node_proposal_count(
            &self.http,
            &self.klever_node_url,
            &self.contract_address,
        )
        .await?;
        let last_scanned = self.read_last_scanned_total();
        if total <= last_scanned {
            return Ok((Vec::new(), last_scanned));
        }

        let mut new_ids = Vec::new();
        // Kept as u64 throughout (re-audit finding N8): `last_scanned`
        // and `total` are both u64 and, while a proposal count anywhere
        // near u32::MAX is not realistic, there is no reason to risk a
        // truncating cast or an overflowing `+=` on the loop variable
        // itself when the only place a u32 is actually required is the
        // `list_node_proposals` call argument below.
        let mut offset: u64 = last_scanned;
        let mut pages = 0u32;
        while offset < total && pages < MAX_DISCOVERY_PAGES_PER_TICK {
            let page_offset: u32 = offset.try_into().unwrap_or(u32::MAX);
            let page = sc_views::list_node_proposals(
                &self.http,
                &self.klever_node_url,
                &self.contract_address,
                page_offset,
                PAGE_SIZE,
            )
            .await?;
            if page.is_empty() {
                warn!(
                    offset,
                    total,
                    "governance_autoexec: empty listNodeProposals page within a known-nonempty \
                     range (likely every row in it failed lenient decode) — continuing past it"
                );
            }
            for p in &page {
                if !p.executed && p.proposer == self.wallet_address {
                    new_ids.push(p.id);
                }
            }
            offset = offset.saturating_add(u64::from(PAGE_SIZE));
            pages += 1;
        }

        let reached_cap = pages >= MAX_DISCOVERY_PAGES_PER_TICK && offset < total;
        if reached_cap {
            warn!(
                scanned_through = offset,
                total,
                "governance_autoexec: hit MAX_DISCOVERY_PAGES_PER_TICK, resuming next tick"
            );
        }
        // On a full pass, the true known-scanned boundary is `total`
        // (everything up to it has been covered) even though `offset`
        // may have overshot past it — the SC's own `end = min(total,
        // offset+limit)` just returns fewer rows near the end, it
        // doesn't error. On a capped partial pass, `offset` IS the exact
        // boundary reached.
        let new_last_scanned = if reached_cap { offset } else { total };

        Ok((new_ids, new_last_scanned))
    }

    /// Re-fetch current on-chain status for each tracked proposal id
    /// directly — `list_node_proposals(offset = id - 1, limit = 1)`
    /// always addresses exactly proposal `id` (ids are 1-based, dense,
    /// and never cleared — see `smart-contract`'s `list_node_proposals`,
    /// `start = offset + 1`). One request per id rather than a single
    /// batched call: this node's own open-proposal count is small
    /// (on-chain default cap is 5), and a failure on one id shouldn't
    /// block checking the others.
    async fn fetch_tracked_proposals(&self, ids: &[u64]) -> Vec<ProposalSummary> {
        let mut out = Vec::with_capacity(ids.len());
        for &id in ids {
            if id == 0 {
                continue;
            }
            let offset: u32 = (id - 1).try_into().unwrap_or(u32::MAX);
            match sc_views::list_node_proposals(
                &self.http,
                &self.klever_node_url,
                &self.contract_address,
                offset,
                1,
            )
            .await
            {
                Ok(mut page) => {
                    if let Some(p) = page.pop() {
                        out.push(p);
                    } else {
                        // Empty result shouldn't happen (nothing ever
                        // clears a node_proposal) unless this one row
                        // failed lenient decoding (sc_views's per-row
                        // skip) or it's a transient RPC gap — log rather
                        // than fail silently (re-audit finding N6), and
                        // just skip this id for this tick rather than
                        // dropping it from the tracked set.
                        warn!(
                            proposal_id = id,
                            "governance_autoexec: status fetch returned no row for a tracked id; will retry next tick"
                        );
                    }
                }
                Err(e) => {
                    debug!(proposal_id = id, error = %e, "governance_autoexec: status fetch failed; will retry next tick");
                }
            }
        }
        out
    }

    /// Returns `true` when the proposal reached a terminal state
    /// (executed — by us or by someone else — or genuinely `failed`)
    /// and should stop being tracked; `false` otherwise (`open`, or
    /// `closed` but still backing off / just attempted and not yet
    /// resolved).
    async fn maybe_execute(&mut self, p: &ProposalSummary, now: u64) -> bool {
        let status = proposal_status(p.executed, p.expires_at, now, p.quorum_met, p.supermajority_met);
        let key = backoff_key(p.id);
        match status {
            "executed" => {
                // Someone else (e.g. a manual dashboard click) executed
                // it since we last checked, without us ever attempting
                // and hitting the "already executed" error path below.
                self.delete_backoff(p.id, &key);
                return true;
            }
            "failed" => {
                // Will never pass — nothing left to do.
                self.delete_backoff(p.id, &key);
                return true;
            }
            "open" => return false,
            _ => {} // "closed" — fall through to the attempt below.
        }

        let next_attempt_at = self
            .storage
            .get_cf(cf::NODE_STATE, &key)
            .ok()
            .flatten()
            .map(|b| BackoffState::decode(&b).next_attempt_at)
            .unwrap_or(0);
        if now < next_attempt_at {
            return false;
        }

        info!(proposal_id = p.id, "governance_autoexec: attempting executeNodeProposal");
        match self.submit_execute(p.id).await {
            Ok(tx_hash) => {
                info!(proposal_id = p.id, tx_hash = %tx_hash, "governance_autoexec: executed");
                self.delete_backoff(p.id, &key);
                true
            }
            Err(e) => self.handle_execute_error(p.id, &e, now).await,
        }
    }

    /// Submit `executeNodeProposal@{id}` through the shared
    /// `governance_submit` channel — same call-data format and the same
    /// single-deadline enqueue+reply shape as
    /// `crate::api::admin::submit_signed_call`, minus the HTTP-status
    /// mapping and the inflight-dedup guard (that guard lives on
    /// `AppState`, which this task deliberately doesn't depend on — see
    /// module doc; the cost of a rare double-attempt racing a manual
    /// click is one harmless "Already executed" revert, already
    /// accepted by design).
    async fn submit_execute(&self, proposal_id: u64) -> Result<String, String> {
        let call_data = format!("executeNodeProposal@{}", encode_u64_calldata_arg(proposal_id));
        let (reply_tx, reply_rx) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        match tokio::time::timeout_at(
            deadline,
            self.governance_submit.send(GovernanceSubmitRequest {
                call_data,
                reply: reply_tx,
            }),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err("anchoring task not running".to_string()),
            Err(_) => return Err("timed out queuing governance submission".to_string()),
        }
        match tokio::time::timeout_at(deadline, reply_rx).await {
            Ok(Ok(inner)) => inner,
            Ok(Err(_)) => Err("anchoring task dropped reply channel".to_string()),
            Err(_) => Err("timed out waiting for governance submission reply".to_string()),
        }
    }

    /// Returns `true` when the proposal is now terminal (an "already
    /// executed" race), `false` when it should stay tracked for a
    /// future retry (funds-blocked or an unclassified failure, both
    /// backed off — see module doc).
    async fn handle_execute_error(&mut self, proposal_id: u64, err: &str, now: u64) -> bool {
        let key = backoff_key(proposal_id);
        if is_already_executed_error(err) {
            info!(proposal_id, "governance_autoexec: already executed by someone else");
            self.delete_backoff(proposal_id, &key);
            return true;
        }
        let (retry_secs, log_msg) = if is_insufficient_funds_error(err) {
            self.fire_funds_blocked_alert(proposal_id).await;
            (
                self.funds_retry_interval.as_secs(),
                "governance_autoexec: insufficient balance to execute proposal",
            )
        } else {
            (
                UNKNOWN_ERROR_RETRY_INTERVAL.as_secs(),
                "governance_autoexec: execute attempt failed, will retry with backoff",
            )
        };
        warn!(proposal_id, error = %err, "{}", log_msg);
        let state = BackoffState {
            next_attempt_at: now + retry_secs,
        };
        if let Err(e) = self.storage.put_cf(cf::NODE_STATE, &key, &state.encode()) {
            warn!(proposal_id, error = %e, "governance_autoexec: failed to persist backoff state");
        }
        false
    }

    /// Fired on every funds-blocked attempt — deliberately NOT gated by
    /// a persisted per-proposal "already notified" flag. See module doc
    /// for why: `AlertEngine`'s own per-`AlertType` cooldown is the
    /// dedup mechanism, matching how every other event-driven alert in
    /// this codebase (e.g. `MetadataDriftDetected`) already works.
    async fn fire_funds_blocked_alert(&self, proposal_id: u64) {
        let Some(tx) = self.alert_event_tx.as_ref() else {
            return;
        };
        let details = format!(
            "Auto-execution of node governance proposal #{proposal_id} failed: insufficient \
             balance in the anchor wallet to pay the transaction fee. Top up the wallet — \
             auto-retry will keep trying every {}h, or execute manually from the dashboard.",
            self.funds_retry_interval.as_secs() / 3600,
        );
        if let Err(e) = tx.try_send(AlertEvent {
            alert_type: AlertType::GovernanceProposalExecuteFundsBlocked,
            details,
        }) {
            debug!(error = %e, "governance_autoexec: alert channel full or closed; dropping");
        }
    }

    /// Best-effort cleanup of a proposal's backoff entry — logged, not
    /// silently discarded (Security Audit finding, l2-node 0.134.0: an
    /// earlier draft used `let _ = ...` on every persistence call in
    /// this module, so a RocksDB failure here would leave a stale
    /// `next_attempt_at` around with no operator-visible signal).
    fn delete_backoff(&self, proposal_id: u64, key: &[u8]) {
        if let Err(e) = self.storage.delete_cf(cf::NODE_STATE, key) {
            warn!(proposal_id, error = %e, "governance_autoexec: failed to clear backoff state");
        }
    }

    fn load_tracked_ids(&self) -> Vec<u64> {
        match self.storage.get_cf(cf::NODE_STATE, TRACKED_IDS_KEY) {
            Ok(Some(bytes)) => decode_ids(&bytes),
            Ok(None) => Vec::new(),
            Err(e) => {
                warn!(error = %e, "governance_autoexec: failed to read tracked proposal ids; assuming none");
                Vec::new()
            }
        }
    }

    fn save_tracked_ids(&self, ids: &[u64]) {
        if let Err(e) = self.storage.put_cf(cf::NODE_STATE, TRACKED_IDS_KEY, &encode_ids(ids)) {
            warn!(error = %e, "governance_autoexec: failed to persist tracked proposal ids");
        }
    }

    fn read_last_scanned_total(&self) -> u64 {
        match self.storage.get_cf(cf::NODE_STATE, LAST_SCANNED_TOTAL_KEY) {
            Ok(Some(bytes)) if bytes.len() >= 8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&bytes[0..8]);
                u64::from_be_bytes(b)
            }
            _ => 0,
        }
    }

    fn write_last_scanned_total(&self, total: u64) {
        if let Err(e) =
            self.storage
                .put_cf(cf::NODE_STATE, LAST_SCANNED_TOTAL_KEY, &total.to_be_bytes())
        {
            warn!(error = %e, "governance_autoexec: failed to persist last-scanned-total");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_insufficient_funds_variants() {
        assert!(is_insufficient_funds_error("insufficient funds for gas"));
        assert!(is_insufficient_funds_error("Sender balance too low to cover fees"));
        assert!(is_insufficient_funds_error("wallet has not enough KLV to pay fee"));
        assert!(!is_insufficient_funds_error("Quorum not reached"));
        assert!(!is_insufficient_funds_error("Voting not ended"));
    }

    #[test]
    fn detects_already_executed() {
        assert!(is_already_executed_error("Already executed"));
        assert!(is_already_executed_error("execution reverted: Already executed"));
        assert!(!is_already_executed_error("Voting not ended"));
    }

    #[test]
    fn backoff_state_roundtrips() {
        let s = BackoffState {
            next_attempt_at: 1_726_000_000,
        };
        assert_eq!(BackoffState::decode(&s.encode()), s);

        let s2 = BackoffState { next_attempt_at: 0 };
        assert_eq!(BackoffState::decode(&s2.encode()), s2);
    }

    #[test]
    fn backoff_state_decode_defaults_on_short_bytes() {
        assert_eq!(BackoffState::decode(&[]), BackoffState::default());
        assert_eq!(BackoffState::decode(&[1, 2, 3]), BackoffState::default());
    }

    #[test]
    fn backoff_key_is_prefixed_and_id_specific() {
        let k1 = backoff_key(1);
        let k2 = backoff_key(2);
        assert!(k1.starts_with(BACKOFF_KEY_PREFIX));
        assert_ne!(k1, k2);
    }

    #[test]
    fn tracked_ids_roundtrip_through_encode_decode() {
        let ids = vec![1u64, 42, 1_000_000];
        assert_eq!(decode_ids(&encode_ids(&ids)), ids);
        assert_eq!(decode_ids(&[]), Vec::<u64>::new());
    }

    #[test]
    fn page_size_never_exceeds_the_sc_hard_limit() {
        // Regression guard for the finding that made this whole task a
        // silent no-op: PAGE_SIZE must never exceed the contract's
        // `LIST_PROPOSALS_MAX_LIMIT` (20 as of smart-contract 0.11.0) —
        // a larger value makes every `listNodeProposals` call revert
        // server-side, which `list_proposals_generic` treats as an
        // EMPTY page rather than an error, so the task would silently
        // find nothing, forever.
        assert!(PAGE_SIZE <= 20, "PAGE_SIZE must not exceed the SC's LIST_PROPOSALS_MAX_LIMIT");
    }
}
