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
            | AlertType::ScSyncBehind => AlertSeverity::Warning,
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
    ) -> Self {
        Self {
            config,
            last_sent: HashMap::new(),
            http: reqwest::Client::new(),
            node_id,
            history: Arc::new(RwLock::new(VecDeque::new())),
            events_rx,
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

        // IPFS unreachable
        if !snap.ipfs_connected {
            self.fire(AlertType::IpfsUnreachable, "IPFS daemon is not reachable").await;
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
    }

    /// Check cooldown and dispatch an alert if allowed.
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
        // Ogmara channel dispatcher would be added here (Phase 6)
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
