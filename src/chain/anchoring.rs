//! State anchoring — periodically submits L2 state roots to the Klever blockchain.
//!
//! Computes a Merkle root of L2 state (users, channels, delegations) and invokes
//! the `anchorState` endpoint on the Ogmara KApp smart contract. This creates an
//! on-chain trust anchor proving the L2 state at a point in time.
//!
//! TX flow (verified on Klever testnet):
//! 1. Build TX via POST /transaction/send
//! 2. Decode TX hash via POST /transaction/decode
//! 3. Sign raw hash bytes with Ed25519
//! 4. Broadcast via POST /transaction/broadcast

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::config::{AnchoringConfig, KleverConfig};
use crate::crypto;
use crate::crypto::signing;
use crate::notifications::alerts::{AlertEvent, AlertEventSender, AlertType};
use crate::storage::rocks::Storage;
use crate::storage::schema::state_keys;

/// Cap on `divergence_observed` HashSet — bounds memory if the SC
/// stalls and lots of heights enter divergence without resolution.
/// At a 1-hour anchor interval, 1000 entries ≈ 42 days of unresolved
/// divergence before the oldest get pruned (logged at warn).
const MAX_DIVERGENCE_OBSERVED: usize = 1000;

/// A submission this node made that has not yet been observed reaching
/// (or failing to reach) canonical status on-chain. The divergence
/// watcher walks this list every `DIVERGENCE_CHECK_INTERVAL` and
/// resolves each entry by querying `getCanonicalAnchor(height)`.
#[derive(Debug, Clone)]
struct PendingSubmission {
    block_height: u64,
    our_root: String,
}

/// Cap on `pending_submissions` size — bounds memory under sustained
/// Klever RPC failure. Each entry is ~80 bytes; 100 entries ≈ 8 KB.
/// At a 1-hour anchor interval that's ~4 days of unresolved
/// submissions before the oldest get dropped (logged at warn).
const MAX_PENDING_SUBMISSIONS: usize = 100;

/// How often the divergence watcher walks `pending_submissions` and
/// queries `getCanonicalAnchor` for each. 5 minutes is well below
/// the default 1-hour anchor interval, fast enough that an alert
/// fires within a few minutes of a real divergence, and slow enough
/// that the Klever RPC load is bounded (~12 walks/hour × ≤ 100
/// entries = ≤ 1200 view calls/hour worst-case per node).
const DIVERGENCE_CHECK_INTERVAL: Duration = Duration::from_secs(300);

/// Background service that anchors L2 state to the Klever blockchain.
pub struct StateAnchorer {
    klever: KleverConfig,
    config: AnchoringConfig,
    http: reqwest::Client,
    storage: Storage,
    signing_key: SigningKey,
    node_id: String,
    sender_address: String,
    consecutive_failures: u32,
    /// Submissions awaiting on-chain canonical resolution. Pushed by
    /// `perform_anchor` on success; drained by `check_divergence`
    /// each `DIVERGENCE_CHECK_INTERVAL` tick. Capped to
    /// `MAX_PENDING_SUBMISSIONS` so a long Klever outage doesn't
    /// inflate node memory — oldest entries dropped with a warn.
    pending_submissions: VecDeque<PendingSubmission>,
    /// Consecutive canonicalized heights at which our submitted root
    /// disagreed with the on-chain canonical root (spec 12 §6.1).
    /// Shared with `AppState` and `MetricsCollector` so the alert
    /// engine can fire `anchor_divergence` when this crosses
    /// `anchor_divergence_consecutive`.
    divergence_counter: Arc<AtomicU32>,
    /// Lifetime count of our submissions that reached canonical
    /// status with a matching root. Process-local; resets across
    /// restarts. Exposed via `/admin/node/registration`'s
    /// `canonical_count` field.
    canonical_counter: Arc<AtomicU64>,
    /// Heights where we observed a mismatch against the on-chain
    /// canonical and which have not yet been resolved via hybrid
    /// escalation. Polled each tick via `isDivergenceEscalated`; when
    /// the SC reports escalation, the watcher fires the
    /// `anchor_divergence_resolved` info alert and removes the entry.
    /// Capped at `MAX_DIVERGENCE_OBSERVED` (oldest dropped on overflow).
    divergence_observed: HashSet<u64>,
    /// Optional sender for one-shot event alerts (resolved divergence).
    /// `None` when the operator runs with `alerts.enabled = false` —
    /// in that case the watcher logs but does not fire alerts.
    alert_event_tx: Option<AlertEventSender>,
}

impl StateAnchorer {
    /// Create a new state anchorer.
    ///
    /// `divergence_counter` and `canonical_counter` are typically
    /// cloned from `AppState` so the metrics collector and admin
    /// endpoint observe the same values the watcher writes.
    pub fn new(
        klever: KleverConfig,
        config: AnchoringConfig,
        storage: Storage,
        signing_key: SigningKey,
        node_id: String,
        divergence_counter: Arc<AtomicU32>,
        canonical_counter: Arc<AtomicU64>,
        alert_event_tx: Option<AlertEventSender>,
    ) -> Result<Self> {
        let sender_address = crypto::pubkey_to_address(&signing_key.verifying_key())
            .map_err(|e| anyhow::anyhow!("computing anchor wallet address: {}", e))?;

        Ok(Self {
            klever,
            config,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .context("creating HTTP client for anchoring")?,
            storage,
            signing_key,
            node_id,
            sender_address,
            consecutive_failures: 0,
            pending_submissions: VecDeque::new(),
            divergence_counter,
            canonical_counter,
            divergence_observed: HashSet::new(),
            alert_event_tx,
        })
    }

    /// Run the anchoring background loop until shutdown.
    pub async fn run(
        &mut self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        mut trigger_rx: tokio::sync::mpsc::Receiver<
            tokio::sync::oneshot::Sender<Result<String, String>>,
        >,
    ) {
        if !self.config.enabled {
            info!("State anchoring disabled");
            let _ = shutdown_rx.recv().await;
            return;
        }

        if self.klever.node_url.is_empty() || self.klever.contract_address.is_empty() {
            warn!("State anchoring enabled but klever.node_url or klever.contract_address not set");
            let _ = shutdown_rx.recv().await;
            return;
        }

        // Spec 12 §3.1 — wait for on-chain registration before entering
        // the anchor loop. The SC would reject our `anchorState` calls
        // anyway, but checking up front gives the operator a clear
        // log message and avoids a 1-hour wait + failure cycle.
        //
        // This is a best-effort check — the SC view calls might fail
        // (transport, contract not yet upgraded, etc.). On failure we
        // proceed into the loop and rely on per-anchor failure backoff.
        if !self.wait_for_registration(&mut shutdown_rx).await {
            info!("State anchorer shutting down (waiting for registration)");
            return;
        }

        info!(
            address = %self.sender_address,
            interval_seconds = self.config.interval_seconds,
            contract = %self.klever.contract_address,
            "State anchoring started"
        );

        let mut interval =
            tokio::time::interval(Duration::from_secs(self.config.interval_seconds));
        // Skip the first immediate tick — let the node settle before first anchor
        interval.tick().await;

        // Independent divergence-watcher tick. Compares our recent
        // submissions against `getCanonicalAnchor` once each height
        // has had time to canonicalize. Runs more frequently than the
        // anchor interval so the `anchor_divergence` alert can fire
        // within a few minutes of a real divergence (spec 12 §6.1).
        let mut divergence_check = tokio::time::interval(DIVERGENCE_CHECK_INTERVAL);
        // Skip the first immediate tick — let the node anchor at least
        // once before we start asking the chain for canonical roots.
        divergence_check.tick().await;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if self.do_anchor_with_backoff(&mut shutdown_rx).await {
                        info!("State anchorer shutting down (during backoff)");
                        break;
                    }
                }
                Some(reply_tx) = trigger_rx.recv() => {
                    info!("Manual anchor trigger received");
                    let result = self.perform_anchor().await;
                    match &result {
                        Ok(tx_hash) => {
                            self.consecutive_failures = 0;
                            let _ = reply_tx.send(Ok(tx_hash.clone()));
                        }
                        Err(e) => {
                            let _ = reply_tx.send(Err(e.to_string()));
                        }
                    }
                }
                _ = divergence_check.tick() => {
                    self.check_divergence().await;
                }
                _ = shutdown_rx.recv() => {
                    info!("State anchorer shutting down");
                    break;
                }
            }
        }
    }

    /// Walk `pending_submissions` and resolve each entry against
    /// `getCanonicalAnchor(height)`:
    ///   - Match → reset `divergence_counter` to 0, bump `canonical_counter`, drop entry.
    ///   - Divergence → bump `divergence_counter`, log warn, drop entry.
    ///   - Not yet canonical (Ok(None)) → keep entry for the next tick.
    ///   - Transport error → keep entry, log debug.
    ///
    /// The divergence counter tracks **consecutive** canonicalized
    /// heights at which our root disagreed — so a single match resets
    /// the streak. Matches the spec 10 §9.2 alert semantics
    /// (`anchor_divergence_consecutive`).
    async fn check_divergence(&mut self) {
        // Phase 2 (v0.44.0): first walk previously-divergent heights to
        // see if the SC has now entered escalated mode and produced a
        // resolution (escalated quorum OR §2.9 tiebreak). Fires the
        // `anchor_divergence_resolved` info alert for each newly-
        // resolved entry. Bounded by `MAX_DIVERGENCE_OBSERVED` —
        // entries that stay unresolved indefinitely are pruned LIFO
        // to keep the set finite.
        self.poll_divergence_resolutions().await;

        if self.pending_submissions.is_empty() {
            return;
        }
        // Drain into a new deque, push-back the ones we keep.
        let drained: Vec<PendingSubmission> = self.pending_submissions.drain(..).collect();
        let mut keep: VecDeque<PendingSubmission> = VecDeque::with_capacity(drained.len());
        for sub in drained {
            match crate::chain::sc_views::get_canonical_anchor(
                &self.http,
                &self.klever.node_url,
                &self.klever.contract_address,
                sub.block_height,
            )
            .await
            {
                Ok(Some(canonical)) => {
                    if canonical.eq_ignore_ascii_case(&sub.our_root) {
                        // Reset the consecutive-divergence streak; bump
                        // the lifetime canonical counter.
                        self.divergence_counter.store(0, Ordering::Relaxed);
                        self.canonical_counter.fetch_add(1, Ordering::Relaxed);
                        info!(
                            block_height = sub.block_height,
                            "Anchor canonicalized — our root matches"
                        );
                    } else {
                        let consecutive =
                            self.divergence_counter.fetch_add(1, Ordering::Relaxed) + 1;
                        warn!(
                            block_height = sub.block_height,
                            ours = %sub.our_root,
                            canonical = %canonical,
                            consecutive,
                            "ANCHOR DIVERGENCE: local root differs from on-chain canonical"
                        );
                        // Phase 2 (v0.44.0): track this height in
                        // `divergence_observed` so the next ticks can
                        // detect when the SC resolves it via the §2.8
                        // escalation path and fire the
                        // `anchor_divergence_resolved` info alert.
                        // Bounded — overflow drops the lowest height
                        // (LIFO retention favors the most recent
                        // disagreements, which are operationally most
                        // interesting).
                        self.track_observed_divergence(sub.block_height);
                    }
                    // Either way: this height has a definitive answer. Drop.
                }
                Ok(None) => {
                    // Not yet canonicalized; keep waiting.
                    keep.push_back(sub);
                }
                Err(e) => {
                    debug!(
                        error = %e,
                        block_height = sub.block_height,
                        "getCanonicalAnchor failed; will retry on next divergence-check tick"
                    );
                    keep.push_back(sub);
                }
            }
        }
        self.pending_submissions = keep;
    }

    /// Walk `divergence_observed` and check each height for hybrid-
    /// escalation resolution. Fires `anchor_divergence_resolved` (info)
    /// for each newly-resolved entry and removes it from the set.
    /// Skipped silently when no entries are tracked (the common case
    /// in a healthy network).
    async fn poll_divergence_resolutions(&mut self) {
        if self.divergence_observed.is_empty() {
            return;
        }
        let heights: Vec<u64> = self.divergence_observed.iter().copied().collect();
        for height in heights {
            // Is this height now in escalated mode? If not, leave it
            // tracked — the SC's `divergence_escalated` flag is
            // one-shot per height and only flips once a SECOND root
            // hits base quorum.
            let escalated = match crate::chain::sc_views::is_divergence_escalated(
                &self.http,
                &self.klever.node_url,
                &self.klever.contract_address,
                height,
            )
            .await
            {
                Ok(b) => b,
                Err(e) => {
                    debug!(error = %e, height, "isDivergenceEscalated failed; will retry");
                    continue;
                }
            };
            if !escalated {
                continue;
            }
            // Escalated. Fetch the (possibly now-resolved) canonical.
            // `getCanonicalAnchor` returns escalated_canonical if set,
            // the §2.9 tiebreak winner if not, or `None` if neither
            // (escalated flag set with no candidates — defensive).
            let canonical = match crate::chain::sc_views::get_canonical_anchor(
                &self.http,
                &self.klever.node_url,
                &self.klever.contract_address,
                height,
            )
            .await
            {
                Ok(Some(c)) => c,
                Ok(None) => continue, // Still unresolved despite escalation flag — wait.
                Err(e) => {
                    debug!(error = %e, height, "getCanonicalAnchor failed during resolution poll");
                    continue;
                }
            };
            // Resolved. Remove from tracking and fire the info alert.
            // Note: we don't know from views alone whether resolution
            // was via escalated_quorum (kind=1) or tiebreak (kind=2);
            // both look identical (escalated_canonical is set). The
            // alert message keeps to the observability framing.
            self.divergence_observed.remove(&height);
            info!(
                height,
                canonical = %canonical,
                "Hybrid quorum resolved a previously-divergent height"
            );
            self.fire_event_alert(
                AlertType::AnchorDivergenceResolved,
                format!(
                    "Height {} resolved on-chain via hybrid quorum. Canonical root: {}",
                    height, canonical
                ),
            );
        }
    }

    /// Add a height to `divergence_observed`, evicting the
    /// lowest-numbered height on overflow. Block heights increase
    /// monotonically with chain progress, so "lowest" effectively
    /// means "oldest" for normal anchoring traffic; the eviction
    /// rule favors more-recent (= operationally more interesting)
    /// divergences. Edge case: an operator who backfills via
    /// snapshot bootstrap may see low-numbered historical heights
    /// enter divergence later — those would be evicted first, which
    /// is a known limitation flagged in Security Audit N4.
    fn track_observed_divergence(&mut self, height: u64) {
        if self.divergence_observed.len() >= MAX_DIVERGENCE_OBSERVED
            && !self.divergence_observed.contains(&height)
        {
            if let Some(&lowest) = self.divergence_observed.iter().min() {
                self.divergence_observed.remove(&lowest);
                warn!(
                    pruned_height = lowest,
                    "divergence_observed full ({}), pruned oldest height",
                    MAX_DIVERGENCE_OBSERVED
                );
            }
        }
        self.divergence_observed.insert(height);
    }

    /// Best-effort send to the AlertEngine's event channel. Uses
    /// `try_send` so the watcher never blocks on a slow AlertEngine.
    /// Drops the event (with a debug log) if the channel is full or
    /// the engine is disabled.
    fn fire_event_alert(&self, alert_type: AlertType, details: String) {
        let Some(tx) = self.alert_event_tx.as_ref() else {
            return;
        };
        let event = AlertEvent {
            alert_type,
            details,
        };
        if let Err(e) = tx.try_send(event) {
            debug!(error = %e, "Alert event channel full or closed; dropping event");
        }
    }

    /// Wait until the node's anchorer wallet is registered on-chain
    /// (spec 12 §3.1). Returns `true` to proceed into the anchor loop,
    /// `false` if the caller should bail (shutdown signal received).
    ///
    /// On a registered network the first call typically returns `true`
    /// immediately and we incur a single SC view RPC. On a fresh node
    /// this loops with a 60-second cadence until the operator registers
    /// via the dashboard.
    ///
    /// View-call failures (transport errors, contract not yet upgraded
    /// to v0.3.0) are logged and treated as "registered=false" — we
    /// keep polling rather than entering the anchor loop blind. The
    /// dashboard's /admin/node/registration endpoint surfaces the
    /// same status to the operator.
    async fn wait_for_registration(
        &self,
        shutdown_rx: &mut tokio::sync::broadcast::Receiver<()>,
    ) -> bool {
        let mut first = true;
        loop {
            match crate::chain::sc_views::is_node_registered(
                &self.http,
                &self.klever.node_url,
                &self.klever.contract_address,
                &self.sender_address,
            )
            .await
            {
                Ok(true) => return true,
                Ok(false) => {
                    if first {
                        warn!(
                            address = %self.sender_address,
                            contract = %self.klever.contract_address,
                            "Anchor wallet is NOT registered on-chain. Anchoring will not start \
                             until the operator registers via the dashboard's Anchoring tab. \
                             Re-checking every 60s.",
                        );
                        first = false;
                    } else {
                        debug!(address = %self.sender_address, "Still not registered; will re-check");
                    }
                }
                Err(e) => {
                    warn!(
                        address = %self.sender_address,
                        contract = %self.klever.contract_address,
                        error = %e,
                        "Failed to query isNodeRegistered (treated as not-registered for now); will retry"
                    );
                }
            }
            // Sleep with shutdown awareness — 60s default re-poll cadence.
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(60)) => continue,
                _ = shutdown_rx.recv() => return false,
            }
        }
    }

    /// Perform anchor with backoff on failure.
    ///
    /// Backoff is implemented with a nested `tokio::select!` so shutdown signals
    /// are still processed promptly during the sleep.
    async fn do_anchor_with_backoff(
        &mut self,
        shutdown_rx: &mut tokio::sync::broadcast::Receiver<()>,
    ) -> bool {
        match self.perform_anchor().await {
            Ok(tx_hash) => {
                self.consecutive_failures = 0;
                info!(tx_hash = %tx_hash, "State anchor submitted successfully");
                false
            }
            Err(e) => {
                self.consecutive_failures += 1;
                let backoff_secs = (30u64 * (1u64 << self.consecutive_failures.min(4))).min(300);
                error!(
                    error = %e,
                    consecutive_failures = self.consecutive_failures,
                    backoff_seconds = backoff_secs,
                    "State anchoring failed"
                );
                // Sleep with shutdown awareness
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(backoff_secs)) => false,
                    _ = shutdown_rx.recv() => true,
                }
            }
        }
    }

    /// Perform a single state anchor: compute root, build TX, sign, broadcast.
    /// On success the (block_height, our_root) tuple is pushed onto
    /// `pending_submissions` so the divergence watcher can later
    /// resolve it against the on-chain canonical anchor.
    async fn perform_anchor(&mut self) -> Result<String> {
        // Step 1: Compute state root (blocking operation — iterate RocksDB)
        let storage = self.storage.clone();
        let (state_root, message_count, channel_count, user_count) =
            tokio::task::spawn_blocking(move || storage.compute_current_state_root())
                .await
                .context("spawn_blocking panicked")?
                .context("computing state root")?;

        let state_root_hex = hex::encode(state_root);
        let block_height = self.storage.get_chain_cursor()
            .context("reading chain cursor for anchor block height")?;

        debug!(
            block_height,
            state_root = %state_root_hex,
            message_count,
            channel_count,
            user_count,
            "State root computed for anchoring"
        );

        // Step 2: Get sender nonce
        let nonce = self.get_nonce().await?;

        // Step 3: Build SC call data (6 args — timestamp is generated by the SC)
        let call_data = self.build_sc_call_data(
            block_height,
            &state_root_hex,
            message_count,
            channel_count,
            user_count,
        );
        let data_b64 = BASE64.encode(&call_data);

        // Step 4: Build and send raw TX
        let raw_tx = self.build_raw_tx(nonce, &data_b64)?;
        let send_resp = self
            .http
            .post(format!("{}/transaction/send", self.klever.node_url))
            .json(&raw_tx)
            .send()
            .await
            .context("POST /transaction/send")?;

        // Note: Klever /transaction/send can return HTTP 200 with both error and data fields.
        // Only treat HTTP-level errors (5xx, network) as failures.
        let send_status = send_resp.status();
        let send_text = send_resp.text().await.context("reading /transaction/send body")?;
        let send_body: Value = serde_json::from_str(&send_text)
            .with_context(|| format!("/transaction/send returned non-JSON (HTTP {}): {}", send_status, &send_text[..send_text.len().min(500)]))?;
        if send_status.is_server_error() {
            let err_msg = send_body.get("error").and_then(|e| e.as_str()).unwrap_or("server error");
            return Err(anyhow::anyhow!("TX send HTTP {}: {}", send_status, err_msg));
        }
        debug!(response = %send_body, "TX send response");

        // Extract the raw TX result — /transaction/send may return error + data simultaneously
        let tx_result = send_body
            .get("data")
            .and_then(|d| d.get("result"))
            .ok_or_else(|| {
                let err_msg = send_body
                    .get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("unknown error");
                anyhow::anyhow!("TX build failed: {}", err_msg)
            })?
            .clone();

        // Step 5: Decode TX to get the hash (send the raw TX object directly)
        let decode_resp = self
            .http
            .post(format!("{}/transaction/decode", self.klever.node_url))
            .json(&tx_result)
            .send()
            .await
            .context("POST /transaction/decode")?;

        let decode_status = decode_resp.status();
        let decode_text = decode_resp.text().await.context("reading /transaction/decode body")?;
        debug!(status = %decode_status, body = %decode_text, "TX decode response");

        let decode_json: Value = serde_json::from_str(&decode_text)
            .with_context(|| format!("/transaction/decode returned non-JSON (HTTP {}): {}", decode_status, &decode_text[..decode_text.len().min(500)]))?;
        let tx_hash_hex = decode_json
            .pointer("/data/tx/hash")
            .and_then(|h| h.as_str())
            .ok_or_else(|| anyhow::anyhow!("no hash in /transaction/decode response: {}", decode_text))?;

        debug!(tx_hash = %tx_hash_hex, "TX hash decoded");

        // Step 6: Sign the raw hash bytes with Ed25519
        let hash_bytes: [u8; 32] = hex::decode(tx_hash_hex)
            .context("decoding tx hash hex")?
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("tx hash wrong length: {} bytes", v.len()))?;

        let signature = signing::sign_tx_hash(&self.signing_key, &hash_bytes);
        let sig_b64 = BASE64.encode(signature.to_bytes());

        // Step 7: Broadcast signed TX
        let mut broadcast_tx = tx_result.clone();
        broadcast_tx["Signature"] = serde_json::json!([sig_b64]);

        let broadcast_body = serde_json::json!({ "tx": broadcast_tx });
        debug!(body = %broadcast_body, "Broadcasting signed TX");
        let broadcast_resp = self
            .http
            .post(format!("{}/transaction/broadcast", self.klever.node_url))
            .json(&broadcast_body)
            .send()
            .await
            .context("POST /transaction/broadcast")?;

        let broadcast_json: Value = broadcast_resp.json().await.context("parsing broadcast response")?;

        // Check for broadcast errors
        if let Some(err) = broadcast_json.get("error").and_then(|e| e.as_str()) {
            if !err.is_empty() {
                // Check if we still got a result despite the error
                if broadcast_json.pointer("/data/txsHashes").is_none() {
                    return Err(anyhow::anyhow!("broadcast failed: {}", err));
                }
                warn!(error = %err, "Broadcast returned error but TX may have succeeded");
            }
        }

        // Store last anchor timestamp locally
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Err(e) = self.storage.put_cf(
            crate::storage::schema::cf::NODE_STATE,
            state_keys::LAST_ANCHOR_TS,
            &now.to_be_bytes(),
        ) {
            warn!(error = %e, "Failed to persist last anchor timestamp");
        }

        info!(
            tx_hash = %tx_hash_hex,
            block_height,
            state_root = %state_root_hex,
            message_count,
            channel_count,
            user_count,
            "State anchor broadcast"
        );

        // Record submission for the divergence watcher. Capped to
        // MAX_PENDING_SUBMISSIONS so a long Klever RPC outage doesn't
        // inflate node memory — oldest entries dropped with a warn so
        // the operator notices their pending queue is overflowing.
        self.pending_submissions.push_back(PendingSubmission {
            block_height,
            our_root: state_root_hex.clone(),
        });
        while self.pending_submissions.len() > MAX_PENDING_SUBMISSIONS {
            if let Some(dropped) = self.pending_submissions.pop_front() {
                warn!(
                    dropped_height = dropped.block_height,
                    pending_size = self.pending_submissions.len(),
                    "Divergence-watcher pending queue overflow — Klever RPC has been unreachable for a long time; oldest submission dropped (will not be checked for canonical agreement)"
                );
            }
        }

        Ok(tx_hash_hex.to_string())
    }

    /// Get the current nonce for the sender address from the Klever API.
    async fn get_nonce(&self) -> Result<u64> {
        let url = format!(
            "{}/v1.0/address/{}",
            self.klever.api_url, self.sender_address
        );
        let resp = self.http.get(&url).send().await;

        match resp {
            Ok(r) if r.status().as_u16() == 404 => {
                debug!(address = %self.sender_address, "Account not found, using nonce 0");
                Ok(0)
            }
            Ok(r) => {
                let body: Value = r.json().await.context("parsing nonce response")?;
                let nonce = body
                    .pointer("/data/account/nonce")
                    .and_then(|n| n.as_u64())
                    .unwrap_or(0);
                debug!(address = %self.sender_address, nonce, "Fetched sender nonce");
                Ok(nonce)
            }
            Err(e) => Err(anyhow::anyhow!("fetching nonce: {}", e)),
        }
    }

    /// Build the SC call data string for `anchorState`.
    ///
    /// Format: `anchorState@hexBlockHeight@hexStateRoot@hexMsgCount@hexChanCount@hexUserCount@hexNodeId`
    /// The SC generates the timestamp from the blockchain block context.
    ///
    /// In the `@`-delimited Klever SC call format, the VM hex-decodes each argument.
    /// For `u64`/`u32` args: hex is decoded to big-endian bytes → integer.
    /// For `ManagedBuffer` args (state_root, node_id): hex is decoded to raw bytes.
    /// Since the SC checks `state_root.len() == 64` (expects the hex STRING, not raw bytes),
    /// we must double-hex-encode: hex(ascii_hex_string) so the VM decodes it back to the
    /// 64-char hex string the SC expects.
    fn build_sc_call_data(
        &self,
        block_height: u64,
        state_root_hex: &str,
        message_count: u64,
        channel_count: u32,
        user_count: u32,
    ) -> String {
        // state_root: SC expects ManagedBuffer of length 64 (the hex string, not raw bytes).
        // Double-hex-encode so VM decodes hex → ASCII hex string.
        let state_root_encoded = hex::encode(state_root_hex.as_bytes());
        format!(
            "anchorState@{}@{}@{}@{}@{}@{}",
            encode_u64_hex(block_height),
            state_root_encoded,
            encode_u64_hex(message_count),
            encode_u32_hex(channel_count),
            encode_u32_hex(user_count),
            hex::encode(self.node_id.as_bytes()),
        )
    }

    /// Build the raw TX JSON for a SmartContract invoke.
    ///
    /// Format matches the koperator CLI's verified working format:
    /// - `type: 63` at top level (SmartContract TX type)
    /// - `contracts` array without `contractType` (already implied by top-level type)
    /// - `permID: 0` and `kdaFee: ""` required by the Klever node
    fn build_raw_tx(&self, nonce: u64, data_b64: &str) -> Result<Value> {
        let contract = serde_json::json!({
            "scType": 0,
            "address": self.klever.contract_address,
            "callValue": null
        });
        Ok(serde_json::json!({
            "type": 63,
            "sender": self.sender_address,
            "nonce": nonce,
            "permID": 0,
            "data": [data_b64],
            "contract": contract,
            "contracts": [contract],
            "kdaFee": ""
        }))
    }
}

/// Hex-encode a u64 with minimal even-length hex (Klever SC requires whole bytes).
fn encode_u64_hex(v: u64) -> String {
    if v == 0 {
        "00".to_string()
    } else {
        let trimmed = format!("{:016x}", v).trim_start_matches('0').to_string();
        // Klever SC expects even-length hex (each arg is decoded as bytes)
        if trimmed.len() % 2 != 0 {
            format!("0{}", trimmed)
        } else {
            trimmed
        }
    }
}

/// Hex-encode a u32 with minimal even-length hex.
fn encode_u32_hex(v: u32) -> String {
    if v == 0 {
        "00".to_string()
    } else {
        let trimmed = format!("{:08x}", v).trim_start_matches('0').to_string();
        if trimmed.len() % 2 != 0 {
            format!("0{}", trimmed)
        } else {
            trimmed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_u64_hex() {
        assert_eq!(encode_u64_hex(0), "00");
        assert_eq!(encode_u64_hex(1), "01");           // padded to even
        assert_eq!(encode_u64_hex(1000), "03e8");      // padded to even
        assert_eq!(encode_u64_hex(258), "0102");       // padded to even
        assert_eq!(encode_u64_hex(256), "0100");       // already even
        assert_eq!(encode_u64_hex(0xFF), "ff");        // already even
        assert_eq!(encode_u64_hex(0xABCD), "abcd");    // already even
    }

    #[test]
    fn test_encode_u32_hex() {
        assert_eq!(encode_u32_hex(0), "00");
        assert_eq!(encode_u32_hex(1), "01");           // padded to even
        assert_eq!(encode_u32_hex(20), "14");          // already even
        assert_eq!(encode_u32_hex(11), "0b");          // padded to even
    }

    #[test]
    fn test_build_sc_call_data() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let klever = KleverConfig::default();
        let config = AnchoringConfig::default();
        let storage_dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(storage_dir.path()).unwrap();
        let anchorer = StateAnchorer::new(
            klever,
            config,
            storage,
            signing_key,
            "TestNode123".to_string(),
            std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            None, // alert_event_tx — tests don't need the alert channel
        )
        .unwrap();

        let data = anchorer.build_sc_call_data(
            1000,
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            258,
            20,
            11,
        );

        assert!(data.starts_with("anchorState@"));
        let parts: Vec<&str> = data.split('@').collect();
        assert_eq!(parts.len(), 7); // 6 args + function name
        assert_eq!(parts[0], "anchorState");
        assert_eq!(parts[1], "03e8"); // block_height 1000 (padded to even)
        // state_root is double-hex-encoded (hex of the ASCII hex string)
        assert_eq!(parts[2], hex::encode("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".as_bytes()));
        assert_eq!(parts[3], "0102"); // message_count 258 (padded to even)
        assert_eq!(parts[4], "14");   // channel_count 20 (already even)
        assert_eq!(parts[5], "0b");   // user_count 11 (padded to even)
        assert_eq!(parts[6], hex::encode("TestNode123".as_bytes()));
    }
}
