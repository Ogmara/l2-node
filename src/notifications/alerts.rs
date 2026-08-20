//! Alert system — monitors node health and dispatches notifications.
//!
//! Supports Telegram, Discord, webhook, and Ogmara channel dispatchers.
//! Includes cooldown to prevent alert spam (spec 10-dashboard.md §9).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::AlertsConfig;
use crate::metrics::MetricsSnapshot;

/// Capacity of the cross-task event channel feeding AlertEngine.
/// Sized to absorb a sustained burst — `AnchorDivergenceResolved`
/// can fire once per height in a tight window if the SC resolves
/// many pending escalations simultaneously. Capacity matches the
/// upper bound of `divergence_observed` (1000) so the watcher
/// can drain its full tracking set without dropping events
/// (Security Audit N3).
const ALERT_EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Alert severity levels (spec 10-dashboard.md §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Critical,
    Warning,
    Info,
}

/// An alert condition type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertType {
    KleverDisconnected,
    IpfsUnreachable,
    LowPeerCount,
    DiskUsageHigh,
    MemoryUsageHigh,
    AnchorOverdue,
    /// Local computed state root diverged from the on-chain canonical
    /// root for ≥ `anchor_divergence_consecutive` consecutive
    /// canonicalized heights (spec 12 §6.1, spec 10 §9.2).
    ///
    /// Critical because it means this node's state has materially
    /// drifted from quorum — either a local bug, a corrupt RocksDB,
    /// or (worst case) a colluding-anchorer attack on the canonical
    /// root. Operator must investigate immediately.
    AnchorDivergence,
    /// A previously-divergent height resolved on-chain via the SC's
    /// `anchorDivergenceResolved` event. Observability signal — no
    /// action required (spec 12 §5.4, l2-node 0.44.0+).
    AnchorDivergenceResolved,
    ScSyncBehind,
    HighRateLimitTriggers,
    FailedSignatureSpike,
    NodeStarted,
    /// `network/sc_discovery` successfully dialed at least one new
    /// peer from the on-chain registry during a cold-start window or
    /// bootstrap-stall recovery (spec 13 §4.3, l2-node 0.44.0+).
    /// Confirms the SC-fallback discovery layer engaged.
    BootstrapScFallbackUsed,
    /// `[anchoring.metadata]` background reconciler detected that the
    /// on-chain `getNodeMetadata(self)` differs from the desired
    /// (configured / auto-derived) multiaddr list (spec 13 §6.1, spec
    /// 10 §9.2, l2-node 0.46.0+). Detect-only — operator must click
    /// Publish in the dashboard to reconcile (spec 12 §6.2 no-proxy-
    /// signing rule). Cooldown bounds re-fire to one per hour even
    /// though the reconcile tick is hourly too.
    MetadataDriftDetected,
    /// A GossipSub publish failed because no peers were subscribed to
    /// the target topic — the
    /// [`libp2p::gossipsub::PublishError::NoPeersSubscribedToTopic`]
    /// case (spec 10 §9.2, l2-node 0.46.6+). Surfaced as B4
    /// instrumentation for the asymmetric-propagation diagnosis that
    /// gated the proper fix shipped in l2-node 0.48.4
    /// (`mesh_outbound_min = 0` + per-peer direction telemetry).
    /// Cooldown bounds re-fire so a topic with no subscribers does not
    /// flood the alert log.
    PublishFailedInsufficientPeers,
}

impl AlertType {
    pub fn severity(&self) -> AlertSeverity {
        match self {
            AlertType::KleverDisconnected
            | AlertType::IpfsUnreachable
            | AlertType::AnchorDivergence => AlertSeverity::Critical,
            AlertType::LowPeerCount
            | AlertType::DiskUsageHigh
            | AlertType::MemoryUsageHigh
            | AlertType::AnchorOverdue
            | AlertType::ScSyncBehind
            | AlertType::PublishFailedInsufficientPeers => AlertSeverity::Warning,
            AlertType::HighRateLimitTriggers
            | AlertType::FailedSignatureSpike
            | AlertType::NodeStarted
            | AlertType::AnchorDivergenceResolved
            | AlertType::BootstrapScFallbackUsed
            | AlertType::MetadataDriftDetected => AlertSeverity::Info,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AlertType::KleverDisconnected => "Klever mainnet disconnected",
            AlertType::IpfsUnreachable => "IPFS node unreachable",
            AlertType::LowPeerCount => "Peer count below minimum",
            AlertType::DiskUsageHigh => "Disk usage above threshold",
            AlertType::MemoryUsageHigh => "Memory usage above threshold",
            AlertType::AnchorOverdue => "State anchor overdue",
            AlertType::AnchorDivergence => "State root diverged from canonical",
            AlertType::AnchorDivergenceResolved => "Anchor divergence resolved on-chain",
            AlertType::ScSyncBehind => "SC sync falling behind",
            AlertType::HighRateLimitTriggers => "High rate-limit trigger count",
            AlertType::FailedSignatureSpike => "Failed signature verification spike",
            AlertType::NodeStarted => "Node started",
            AlertType::BootstrapScFallbackUsed => "On-chain peer discovery engaged",
            AlertType::MetadataDriftDetected => "On-chain metadata drifted from configured list",
            AlertType::PublishFailedInsufficientPeers => {
                "GossipSub publish failed — no peers subscribed to topic"
            }
        }
    }

    pub fn condition_name(&self) -> &'static str {
        match self {
            AlertType::KleverDisconnected => "klever_disconnected",
            AlertType::IpfsUnreachable => "ipfs_unreachable",
            AlertType::LowPeerCount => "low_peers",
            AlertType::DiskUsageHigh => "high_disk",
            AlertType::MemoryUsageHigh => "high_memory",
            AlertType::AnchorOverdue => "anchor_overdue",
            AlertType::AnchorDivergence => "anchor_divergence",
            AlertType::AnchorDivergenceResolved => "anchor_divergence_resolved",
            AlertType::ScSyncBehind => "sc_sync_behind",
            AlertType::HighRateLimitTriggers => "high_rate_limits",
            AlertType::FailedSignatureSpike => "high_failed_sigs",
            AlertType::NodeStarted => "node_started",
            AlertType::BootstrapScFallbackUsed => "bootstrap_sc_fallback_used",
            AlertType::MetadataDriftDetected => "metadata_drift_detected",
            AlertType::PublishFailedInsufficientPeers => "publish_failed_insufficient_peers",
        }
    }
}

/// One-shot event-driven alert request, sent from background tasks
/// (divergence-watcher, sc_discovery) to AlertEngine via mpsc channel.
///
/// Unlike the threshold-based alerts evaluated on every 30s tick,
/// event alerts fire once per observable occurrence. Cooldown still
/// applies — the engine deduplicates within `cooldown.seconds`.
#[derive(Debug, Clone)]
pub struct AlertEvent {
    pub alert_type: AlertType,
    pub details: String,
}

/// Sender half of the AlertEngine event channel. Clone freely — it's
/// an mpsc::Sender under the hood.
pub type AlertEventSender = mpsc::Sender<AlertEvent>;

/// An alert record for history tracking.
#[derive(Debug, Clone, Serialize)]
pub struct AlertRecord {
    pub severity: AlertSeverity,
    pub condition: String,
    pub message: String,
    pub triggered_at: u64,
    pub resolved: bool,
}

/// The alerting engine — evaluates thresholds and dispatches alerts.
///
/// Runs as a background task, checking metrics every 30 seconds.
/// Shared alert history accessible from dashboard API handlers.
pub type SharedAlertHistory = Arc<RwLock<VecDeque<AlertRecord>>>;

pub struct AlertEngine {
    config: AlertsConfig,
    /// Last time each alert type was sent (for cooldown).
    last_sent: HashMap<AlertType, Instant>,
    /// HTTP client for webhooks.
    http: reqwest::Client,
    /// Node ID for alert messages.
    node_id: String,
    /// Shared alert history (last 1000 records), readable by the dashboard API.
    history: SharedAlertHistory,
    /// Receive end of the event channel — background tasks push
    /// one-shot info events (divergence_resolved, sc_fallback_used)
    /// via the matching sender.
    events_rx: mpsc::Receiver<AlertEvent>,
    /// `[anchoring] interval_seconds` (audit final pre-mainnet W35) — the
    /// expected anchor cadence, multiplied by `thresholds.anchor_overdue_multiplier`
    /// to get the `AnchorOverdue` firing threshold. `AlertEngine` only holds
    /// `AlertsConfig` otherwise, so this one cross-section value is threaded
    /// in directly rather than duplicated into `AlertThresholds`.
    anchor_interval_seconds: u64,
    /// Local debounce state for `IpfsUnreachable` (audit final pre-mainnet
    /// W35 grace-window fix): when IPFS was first observed disconnected.
    /// `None` while connected. Previously this alert fired on the very
    /// first disconnected reading, ignoring `thresholds.ipfs_disconnect_seconds`
    /// entirely.
    ipfs_disconnected_since: Option<Instant>,
    /// Local rate-tracking state for `FailedSignatureSpike` (audit final
    /// pre-mainnet W35): `(tick_time, cumulative_count)` as of the previous
    /// `evaluate()` call, used to convert the cumulative counter into a
    /// per-minute rate.
    prev_failed_sig_check: Option<(Instant, u64)>,
    /// Same shape as `prev_failed_sig_check`, for `HighRateLimitTriggers`.
    prev_rate_limited_check: Option<(Instant, u64)>,
    /// Audit final pre-mainnet W34: `None` when `[alerts.ogmara_channel]`
    /// is disabled, key-loading failed, or the loaded key's derived
    /// address didn't match the configured `wallet_address` (all
    /// graceful-degrade, not startup failure — see the `node.rs`
    /// construction site).
    channel_dispatcher: Option<crate::notifications::alert_channel::AlertChannelDispatcher>,
    /// Whether `[klever]` (`node_url`/`api_url`/`contract_address`) is
    /// actually configured on this node (Code Audit WARNING #4 fix). Nodes
    /// running fully isolated-subnet (no on-chain integration at all, see
    /// `ChainScanner::run`'s identical predicate) never make a Klever RPC
    /// call, so `klever_rpc_last_success_ms` stays `0` forever by design —
    /// without this gate, `KleverDisconnected` fired at cold start and NEVER
    /// cleared on such a node, a permanent false positive that (once W34
    /// shipped) also spammed the configured alert channel with a message
    /// every cooldown period, forever.
    klever_configured: bool,
}

impl AlertEngine {
    /// Pre-allocate the cross-task alert event channel. The sender
    /// half is cloneable and goes to any task that needs to fire
    /// event-driven alerts (divergence-watcher, sc_discovery). The
    /// receiver goes into `AlertEngine::new` below. Separating channel
    /// construction from engine construction lets callers wire the
    /// sender into tasks that must start BEFORE the alert engine does.
    pub fn event_channel() -> (AlertEventSender, mpsc::Receiver<AlertEvent>) {
        mpsc::channel(ALERT_EVENT_CHANNEL_CAPACITY)
    }

    /// Construct the engine. `events_rx` must come from a paired call
    /// to [`event_channel`]; the engine consumes events posted on the
    /// matching sender.
    pub fn new(
        config: AlertsConfig,
        node_id: String,
        events_rx: mpsc::Receiver<AlertEvent>,
        anchor_interval_seconds: u64,
        channel_dispatcher: Option<crate::notifications::alert_channel::AlertChannelDispatcher>,
        klever_configured: bool,
    ) -> Self {
        Self {
            config,
            last_sent: HashMap::new(),
            http: reqwest::Client::new(),
            node_id,
            history: Arc::new(RwLock::new(VecDeque::new())),
            events_rx,
            anchor_interval_seconds,
            ipfs_disconnected_since: None,
            prev_failed_sig_check: None,
            prev_rate_limited_check: None,
            channel_dispatcher,
            klever_configured,
        }
    }

    /// Get a shared handle to the alert history (for dashboard API).
    pub fn history_handle(&self) -> SharedAlertHistory {
        self.history.clone()
    }

    /// Set an externally created shared history (for sharing with AppState).
    pub fn set_history(&mut self, history: SharedAlertHistory) {
        self.history = history;
    }

    /// Run the alert evaluation loop.
    pub async fn run(
        mut self,
        latest: Arc<std::sync::RwLock<MetricsSnapshot>>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        // Fire node_started alert on startup
        self.fire(AlertType::NodeStarted, "Node process started").await;

        let mut interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let snap = latest.read().map(|s| *s).unwrap_or_default();
                    self.evaluate(&snap).await;
                }
                Some(event) = self.events_rx.recv() => {
                    // Event-driven fire from a background task (e.g.,
                    // sc_discovery success, divergence resolution).
                    // `fire` applies the same cooldown as threshold
                    // alerts so a burst of events still gets
                    // deduplicated within `cooldown.seconds`.
                    self.fire(event.alert_type, &event.details).await;
                }
                _ = shutdown_rx.recv() => {
                    debug!("Alert engine shutting down");
                    break;
                }
            }
        }
    }

    /// Evaluate all alert conditions against the current metrics snapshot.
    async fn evaluate(&mut self, snap: &MetricsSnapshot) {
        // Copy threshold values to avoid borrow conflicts with &mut self in fire()
        let min_peers = self.config.thresholds.min_peers;
        let max_disk_pct = self.config.thresholds.max_disk_usage_percent;
        let max_mem_pct = self.config.thresholds.max_memory_usage_percent;
        let max_sync_lag = self.config.thresholds.sc_sync_max_lag_blocks;
        let divergence_threshold = self.config.thresholds.anchor_divergence_consecutive;

        // IPFS unreachable (audit final pre-mainnet W35: grace-window fix —
        // this used to fire on the very first disconnected reading,
        // ignoring `ipfs_disconnect_seconds` entirely).
        if snap.ipfs_connected {
            self.ipfs_disconnected_since = None;
        } else {
            let since = *self.ipfs_disconnected_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_secs(self.config.thresholds.ipfs_disconnect_seconds) {
                self.fire(AlertType::IpfsUnreachable, "IPFS daemon is not reachable").await;
            }
        }

        // Low peers
        if snap.peers_connected < min_peers {
            self.fire(
                AlertType::LowPeerCount,
                &format!(
                    "Connected peers: {} (threshold: {})",
                    snap.peers_connected, min_peers
                ),
            ).await;
        }

        // High disk usage
        if snap.disk_total_bytes > 0 {
            let pct = ((snap.disk_used_bytes as f64 / snap.disk_total_bytes as f64) * 100.0).min(100.0) as u8;
            if pct >= max_disk_pct {
                self.fire(
                    AlertType::DiskUsageHigh,
                    &format!("Disk usage: {}% (threshold: {}%)", pct, max_disk_pct),
                ).await;
            }
        }

        // High memory usage
        if snap.memory_total_bytes > 0 {
            let pct = ((snap.memory_used_bytes as f64 / snap.memory_total_bytes as f64) * 100.0).min(100.0) as u8;
            if pct >= max_mem_pct {
                self.fire(
                    AlertType::MemoryUsageHigh,
                    &format!("Memory usage: {}% (threshold: {}%)", pct, max_mem_pct),
                ).await;
            }
        }

        // SC sync behind
        if snap.klever_sync_lag_blocks > max_sync_lag {
            self.fire(
                AlertType::ScSyncBehind,
                &format!(
                    "Sync lag: {} blocks (threshold: {})",
                    snap.klever_sync_lag_blocks, max_sync_lag
                ),
            ).await;
        }

        // Anchor divergence — local state root drifted from quorum
        // canonical for ≥ N consecutive heights (spec 12 §6.1).
        //
        // Live as of v0.43.4: `StateAnchorer::check_divergence` walks
        // its pending-submission queue every 5 minutes, querying
        // `getCanonicalAnchor` for each height; on mismatch it bumps
        // the divergence counter (shared via Arc<AtomicU32>), on
        // match it resets the counter. MetricsCollector reads the
        // counter into `snap.anchor_divergence_count` per snapshot.
        if divergence_threshold > 0
            && snap.anchor_divergence_count >= divergence_threshold
        {
            self.fire(
                AlertType::AnchorDivergence,
                &format!(
                    "Anchor divergence: {} consecutive canonical heights diverge from local root (threshold: {})",
                    snap.anchor_divergence_count, divergence_threshold
                ),
            ).await;
        }

        // Klever RPC disconnected (audit final pre-mainnet W35). `0` means
        // never succeeded (cold start) — fires immediately, same convention
        // as the `ipfs_connected` check before its own grace-window existed;
        // unlike IPFS, there's no separate "was it ever briefly true"
        // concept to debounce here, since the underlying signal is already
        // an absolute last-success timestamp, not a boolean.
        //
        // Code Audit WARNING #4 fix: gated on `klever_configured` — a node
        // running without `[klever]` configured (isolated subnet, see
        // `klever_configured`'s doc comment) never makes an RPC call at all,
        // so this would otherwise fire at cold start and never clear.
        if self.klever_configured {
            let klever_disconnect_ms = self.config.thresholds.klever_disconnect_seconds * 1000;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            if now_ms.saturating_sub(snap.klever_rpc_last_success_ms) > klever_disconnect_ms {
                self.fire(
                    AlertType::KleverDisconnected,
                    &format!(
                        "No successful Klever RPC call in over {}s",
                        self.config.thresholds.klever_disconnect_seconds
                    ),
                ).await;
            }
        }

        // Anchor overdue (audit final pre-mainnet W35). `last_anchor_age_seconds`
        // is `0` until the first anchor of this process lifetime lands (see
        // `MetricsCollector::update_latest_snapshot`), so this deliberately
        // does NOT fire on a fresh node still waiting for its first anchor —
        // that's a startup/registration-timing question, not "overdue".
        if snap.last_anchor_age_seconds > 0 && self.anchor_interval_seconds > 0 {
            let overdue_threshold = (self.anchor_interval_seconds as f64
                * self.config.thresholds.anchor_overdue_multiplier) as u64;
            if snap.last_anchor_age_seconds > overdue_threshold {
                self.fire(
                    AlertType::AnchorOverdue,
                    &format!(
                        "Last anchor {}s ago (expected every {}s, threshold {}s)",
                        snap.last_anchor_age_seconds, self.anchor_interval_seconds, overdue_threshold
                    ),
                ).await;
            }
        }

        // Failed-signature spike + high-rate-limit-triggers (audit final
        // pre-mainnet W35): both are cumulative counters that need a
        // per-minute RATE, not an absolute-value comparison — convert via
        // the delta since the previous tick, same debounce-state shape as
        // the two counters above.
        let rate_limit_per_min = self.config.thresholds.rate_limit_alert_per_min;
        let failed_sig_per_min = self.config.thresholds.failed_sig_alert_per_min;
        let now = Instant::now();
        if let Some((prev_time, prev_count)) = self.prev_failed_sig_check {
            let elapsed_min = prev_time.elapsed().as_secs_f64() / 60.0;
            if elapsed_min > 0.0 {
                let rate = (snap.failed_signature_verifications_total.saturating_sub(prev_count)) as f64
                    / elapsed_min;
                if rate >= failed_sig_per_min as f64 {
                    self.fire(
                        AlertType::FailedSignatureSpike,
                        &format!(
                            "{:.0} failed signature verifications/min (threshold: {})",
                            rate, failed_sig_per_min
                        ),
                    ).await;
                }
            }
        }
        self.prev_failed_sig_check = Some((now, snap.failed_signature_verifications_total));

        if let Some((prev_time, prev_count)) = self.prev_rate_limited_check {
            let elapsed_min = prev_time.elapsed().as_secs_f64() / 60.0;
            if elapsed_min > 0.0 {
                let rate = (snap.rate_limited_total.saturating_sub(prev_count)) as f64 / elapsed_min;
                if rate >= rate_limit_per_min as f64 {
                    self.fire(
                        AlertType::HighRateLimitTriggers,
                        &format!(
                            "{:.0} rate-limit triggers/min (threshold: {})",
                            rate, rate_limit_per_min
                        ),
                    ).await;
                }
            }
        }
        self.prev_rate_limited_check = Some((now, snap.rate_limited_total));
    }

    /// Check cooldown and dispatch an alert if allowed.
    ///
    /// **Accepted residual (Security NOTE-1, reviewed + deferred
    /// 2026-08-19)**: an attacker who can remotely trip a threshold-based
    /// alert condition (e.g. deliberately racking up failed-signature or
    /// rate-limit rejections toward `FailedSignatureSpike`/
    /// `HighRateLimitTriggers`) can indirectly cause this node to post a
    /// PUBLIC message via `[alerts.ogmara_channel]` (W34) — the attacker
    /// doesn't choose the message content, only its timing. Judged
    /// acceptable: the per-`AlertType` cooldown below applies UNIFORMLY
    /// regardless of trigger source, capping this to at most one post per
    /// `[alerts.cooldown] seconds` per alert type — the same ceiling that
    /// already bounds a genuine operational incident from spamming the
    /// channel. No separate rate limit needed on top of it.
    async fn fire(&mut self, alert_type: AlertType, details: &str) {
        if !self.config.enabled {
            return;
        }

        let cooldown = Duration::from_secs(self.config.cooldown.seconds);
        if let Some(last) = self.last_sent.get(&alert_type) {
            if last.elapsed() < cooldown {
                return;
            }
        }
        self.last_sent.insert(alert_type, Instant::now());

        let severity = alert_type.severity();
        let severity_str = match severity {
            AlertSeverity::Critical => "CRITICAL",
            AlertSeverity::Warning => "WARNING",
            AlertSeverity::Info => "INFO",
        };

        let message = format!(
            "[Ogmara Node Alert] [{}] {}\nNode: {}\nTime: {}\nDetails: {}",
            severity_str,
            alert_type.description(),
            self.node_id,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            details,
        );

        info!(
            alert_type = alert_type.condition_name(),
            severity = severity_str,
            "Alert fired: {}",
            alert_type.description()
        );

        // Record in shared history (VecDeque for O(1) pop_front)
        let record = AlertRecord {
            severity,
            condition: alert_type.condition_name().to_string(),
            message: details.to_string(),
            triggered_at: chrono::Utc::now().timestamp_millis() as u64,
            resolved: false,
        };
        if let Ok(mut history) = self.history.write() {
            history.push_back(record);
            while history.len() > 1000 {
                history.pop_front();
            }
        }

        // Dispatch to configured channels
        if self.config.telegram.enabled {
            self.send_telegram(&message).await;
        }
        if self.config.discord.enabled {
            self.send_discord(&message).await;
        }
        if self.config.webhook.enabled {
            self.send_webhook(&message).await;
        }
        // Audit final pre-mainnet W34.
        if let Some(dispatcher) = self.channel_dispatcher.as_ref() {
            crate::notifications::alert_channel::dispatch_ogmara_channel_alert(dispatcher, &message)
                .await;
        }
    }

    async fn send_telegram(&self, message: &str) {
        let token = resolve_env_or_value(&self.config.telegram.bot_token);
        let chat_id = &self.config.telegram.chat_id;
        if token.is_empty() || chat_id.is_empty() {
            return;
        }

        let url = format!("https://api.telegram.org/bot{}/sendMessage", token);
        let body = serde_json::json!({
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
        });

        match self.http.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => debug!("Telegram alert sent"),
            Ok(resp) => warn!(status = %resp.status(), "Telegram alert failed"),
            Err(e) => warn!(error = %e, "Telegram alert error"),
        }
    }

    async fn send_discord(&self, message: &str) {
        let url = resolve_env_or_value(&self.config.discord.webhook_url);
        if url.is_empty() {
            return;
        }

        let body = serde_json::json!({ "content": message });
        match self.http.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => debug!("Discord alert sent"),
            Ok(resp) => warn!(status = %resp.status(), "Discord alert failed"),
            Err(e) => warn!(error = %e, "Discord alert error"),
        }
    }

    async fn send_webhook(&self, message: &str) {
        let url = resolve_env_or_value(&self.config.webhook.url);
        if url.is_empty() {
            return;
        }

        let body = serde_json::json!({
            "source": "ogmara-node",
            "node_id": self.node_id,
            "alert": message,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        match self.http.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => debug!("Webhook alert sent"),
            Ok(resp) => warn!(status = %resp.status(), "Webhook alert failed"),
            Err(e) => warn!(error = %e, "Webhook alert error"),
        }
    }
}

/// Resolve a value that might be an environment variable reference.
fn resolve_env_or_value(value: &str) -> String {
    if let Some(var_name) = value.strip_prefix('$') {
        std::env::var(var_name).unwrap_or_default()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    //! Audit final pre-mainnet W35. `AlertsConfig::default()` has every
    //! dispatch channel disabled, so `fire()` no-ops safely (returns before
    //! any HTTP call) — these tests exercise the debounce/rate STATE
    //! machinery in `evaluate()` without needing network access or a real
    //! wall-clock sleep.
    use super::*;
    use crate::config::AlertsConfig;

    fn engine(anchor_interval_seconds: u64) -> AlertEngine {
        engine_with_klever(anchor_interval_seconds, true)
    }

    fn engine_with_klever(anchor_interval_seconds: u64, klever_configured: bool) -> AlertEngine {
        let (_tx, rx) = AlertEngine::event_channel();
        AlertEngine::new(
            AlertsConfig::default(),
            "test-node".to_string(),
            rx,
            anchor_interval_seconds,
            None,
            klever_configured,
        )
    }

    fn snap(overrides: impl FnOnce(&mut MetricsSnapshot)) -> MetricsSnapshot {
        let mut s = MetricsSnapshot::default();
        s.ipfs_connected = true; // sane baseline; individual tests flip what they need
        overrides(&mut s);
        s
    }

    #[tokio::test]
    async fn ipfs_unreachable_does_not_fire_on_first_disconnected_reading() {
        // Regression for the exact pre-fix bug: a nonzero grace window must
        // NOT fire immediately on the first `ipfs_connected = false` tick.
        let mut e = engine(3600);
        e.config.thresholds.ipfs_disconnect_seconds = 3600; // 1h grace window
        let s = snap(|s| s.ipfs_connected = false);
        e.evaluate(&s).await;
        assert!(
            e.ipfs_disconnected_since.is_some(),
            "must start tracking disconnection time on the first bad reading"
        );
        // With a 1h grace window, immediately-after-the-first-tick must not
        // have crossed the threshold yet (would need a real 1h sleep to fire).
    }

    #[tokio::test]
    async fn ipfs_unreachable_resets_when_reconnected() {
        let mut e = engine(3600);
        let disconnected = snap(|s| s.ipfs_connected = false);
        e.evaluate(&disconnected).await;
        assert!(e.ipfs_disconnected_since.is_some());

        let reconnected = snap(|s| s.ipfs_connected = true);
        e.evaluate(&reconnected).await;
        assert!(
            e.ipfs_disconnected_since.is_none(),
            "reconnecting must clear the debounce state, not leave a stale timestamp"
        );
    }

    #[tokio::test]
    async fn klever_disconnected_fires_from_cold_start() {
        let mut e = engine(3600);
        e.config.enabled = true; // so `fire()` actually records into `last_sent` below
        e.config.thresholds.klever_disconnect_seconds = 1;
        // klever_rpc_last_success_ms defaults to 0 (never succeeded) via
        // MetricsSnapshot::default() — must be treated as "very stale", not
        // as a false match against "now".
        let s = snap(|_| {});
        e.evaluate(&s).await;
        assert!(
            e.last_sent.contains_key(&AlertType::KleverDisconnected),
            "a configured node with no successful RPC call ever must fire KleverDisconnected"
        );
    }

    /// Code Audit WARNING #4 regression: a node with `[klever]` unconfigured
    /// (isolated subnet, `klever_configured = false`) never makes an RPC
    /// call, so `klever_rpc_last_success_ms` stays `0` forever by design —
    /// this must NOT be misread as "disconnected" and must never fire, even
    /// though the raw threshold comparison (same as the cold-start test
    /// above) would otherwise trip on the very first `evaluate()`.
    #[tokio::test]
    async fn klever_disconnected_never_fires_when_not_configured() {
        let mut e = engine_with_klever(3600, false);
        e.config.enabled = true;
        e.config.thresholds.klever_disconnect_seconds = 1;
        let s = snap(|_| {});
        e.evaluate(&s).await;
        assert!(
            !e.last_sent.contains_key(&AlertType::KleverDisconnected),
            "KleverDisconnected must never fire when Klever isn't configured on this node"
        );
    }

    #[tokio::test]
    async fn anchor_overdue_does_not_fire_before_first_anchor() {
        // last_anchor_age_seconds == 0 means "no anchor yet this process
        // lifetime" (see MetricsCollector::update_latest_snapshot) — must
        // NOT be misread as "anchored 0 seconds ago, perfectly fresh" in a
        // way that's indistinguishable from "never anchored, wildly overdue".
        // The guard is `> 0`, so this must not fire regardless of interval.
        let mut e = engine(1); // 1-second interval — would be wildly overdue if misread
        let s = snap(|s| s.last_anchor_age_seconds = 0);
        e.evaluate(&s).await; // must not panic or misbehave
    }

    #[tokio::test]
    async fn failed_signature_rate_uses_delta_not_cumulative_total() {
        let mut e = engine(3600);
        e.config.thresholds.failed_sig_alert_per_min = 1_000_000; // effectively unreachable
        let s1 = snap(|s| s.failed_signature_verifications_total = 100);
        e.evaluate(&s1).await;
        assert_eq!(e.prev_failed_sig_check, e.prev_failed_sig_check.map(|(t, _)| (t, 100)));

        // A second tick with a much higher cumulative total — the rate
        // check must use the DELTA (100 -> 500 = 400 over the tick), not
        // treat 500 as an absolute per-minute rate on its own.
        let s2 = snap(|s| s.failed_signature_verifications_total = 500);
        e.evaluate(&s2).await;
        let (_, last_count) = e.prev_failed_sig_check.expect("must track cumulative count");
        assert_eq!(last_count, 500, "must advance the tracked cumulative count each tick");
    }
}
