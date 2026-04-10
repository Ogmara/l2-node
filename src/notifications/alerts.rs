//! Alert system — monitors node health and dispatches notifications.
//!
//! Supports Telegram, Discord, webhook, and Ogmara channel dispatchers.
//! Includes cooldown to prevent alert spam (spec 10-dashboard.md §9).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use tracing::{debug, info, warn};

use crate::config::AlertsConfig;
use crate::metrics::MetricsSnapshot;

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
    ScSyncBehind,
    HighRateLimitTriggers,
    FailedSignatureSpike,
    NodeStarted,
}

impl AlertType {
    pub fn severity(&self) -> AlertSeverity {
        match self {
            AlertType::KleverDisconnected | AlertType::IpfsUnreachable => AlertSeverity::Critical,
            AlertType::LowPeerCount
            | AlertType::DiskUsageHigh
            | AlertType::MemoryUsageHigh
            | AlertType::AnchorOverdue
            | AlertType::ScSyncBehind => AlertSeverity::Warning,
            AlertType::HighRateLimitTriggers
            | AlertType::FailedSignatureSpike
            | AlertType::NodeStarted => AlertSeverity::Info,
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
            AlertType::ScSyncBehind => "SC sync falling behind",
            AlertType::HighRateLimitTriggers => "High rate-limit trigger count",
            AlertType::FailedSignatureSpike => "Failed signature verification spike",
            AlertType::NodeStarted => "Node started",
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
            AlertType::ScSyncBehind => "sc_sync_behind",
            AlertType::HighRateLimitTriggers => "high_rate_limits",
            AlertType::FailedSignatureSpike => "high_failed_sigs",
            AlertType::NodeStarted => "node_started",
        }
    }
}

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
}

impl AlertEngine {
    pub fn new(config: AlertsConfig, node_id: String) -> Self {
        Self {
            config,
            last_sent: HashMap::new(),
            http: reqwest::Client::new(),
            node_id,
            history: Arc::new(RwLock::new(VecDeque::new())),
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
