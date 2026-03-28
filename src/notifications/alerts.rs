//! Alerting system — sends notifications to operators via Telegram, Discord, webhooks.
//!
//! Monitors node health metrics and sends alerts when thresholds are exceeded.
//! Includes cooldown to prevent alert spam (spec 4.5.3).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::Serialize;
use tracing::{debug, info, warn};

use crate::config::AlertsConfig;

/// Alert severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AlertSeverity {
    Error,
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
    NodeRestarted,
}

impl AlertType {
    fn severity(&self) -> AlertSeverity {
        match self {
            AlertType::KleverDisconnected | AlertType::IpfsUnreachable | AlertType::NodeRestarted => {
                AlertSeverity::Error
            }
            AlertType::LowPeerCount
            | AlertType::DiskUsageHigh
            | AlertType::MemoryUsageHigh
            | AlertType::AnchorOverdue
            | AlertType::ScSyncBehind
            | AlertType::FailedSignatureSpike => AlertSeverity::Warning,
            AlertType::HighRateLimitTriggers => AlertSeverity::Info,
        }
    }

    fn description(&self) -> &'static str {
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
            AlertType::NodeRestarted => "Node process restarted",
        }
    }
}

/// The alerting service.
pub struct AlertService {
    config: AlertsConfig,
    /// Last time each alert type was sent (for cooldown).
    last_sent: HashMap<AlertType, Instant>,
    /// HTTP client for webhooks.
    http: reqwest::Client,
    /// Node name for alert messages.
    node_id: String,
}

impl AlertService {
    pub fn new(config: AlertsConfig, node_id: String) -> Self {
        Self {
            config,
            last_sent: HashMap::new(),
            http: reqwest::Client::new(),
            node_id,
        }
    }

    /// Check if an alert should be sent (respects cooldown).
    fn should_send(&mut self, alert_type: AlertType) -> bool {
        if !self.config.enabled {
            return false;
        }

        let cooldown = Duration::from_secs(self.config.cooldown.seconds);

        if let Some(last) = self.last_sent.get(&alert_type) {
            if last.elapsed() < cooldown {
                return false;
            }
        }

        self.last_sent.insert(alert_type, Instant::now());
        true
    }

    /// Fire an alert if cooldown allows it.
    pub async fn fire(&mut self, alert_type: AlertType, details: &str) {
        if !self.should_send(alert_type) {
            return;
        }

        let severity = alert_type.severity();
        let message = format!(
            "[Ogmara Node Alert] [{:?}] {}\nNode: {}\nTime: {}\nDetails: {}",
            severity,
            alert_type.description(),
            self.node_id,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            details,
        );

        info!(
            alert_type = ?alert_type,
            severity = ?severity,
            "Alert fired: {}",
            alert_type.description()
        );

        // Send to configured channels
        if self.config.telegram.enabled {
            self.send_telegram(&message).await;
        }
        if self.config.discord.enabled {
            self.send_discord(&message).await;
        }
        if self.config.webhook.enabled {
            self.send_webhook(&message).await;
        }
    }

    /// Send alert via Telegram Bot API.
    async fn send_telegram(&self, message: &str) {
        let token = resolve_env_or_value(&self.config.telegram.bot_token);
        let chat_id = &self.config.telegram.chat_id;

        if token.is_empty() || chat_id.is_empty() {
            return;
        }

        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            token
        );

        let body = serde_json::json!({
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
        });

        match self.http.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                debug!("Telegram alert sent");
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "Telegram alert failed");
            }
            Err(e) => {
                warn!(error = %e, "Telegram alert error");
            }
        }
    }

    /// Send alert via Discord webhook.
    async fn send_discord(&self, message: &str) {
        let url = resolve_env_or_value(&self.config.discord.webhook_url);
        if url.is_empty() {
            return;
        }

        let body = serde_json::json!({
            "content": message,
        });

        match self.http.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                debug!("Discord alert sent");
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "Discord alert failed");
            }
            Err(e) => {
                warn!(error = %e, "Discord alert error");
            }
        }
    }

    /// Send alert via generic webhook.
    async fn send_webhook(&self, message: &str) {
        let url = resolve_env_or_value(&self.config.webhook.url);
        if url.is_empty() {
            return;
        }

        let body = serde_json::json!({
            "alert": message,
            "node_id": self.node_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        match self.http.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                debug!("Webhook alert sent");
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "Webhook alert failed");
            }
            Err(e) => {
                warn!(error = %e, "Webhook alert error");
            }
        }
    }
}

/// Resolve a value that might be an environment variable reference.
///
/// If the value starts with `$`, treat it as an env var name.
/// Otherwise use the value directly.
fn resolve_env_or_value(value: &str) -> String {
    if let Some(var_name) = value.strip_prefix('$') {
        std::env::var(var_name).unwrap_or_default()
    } else {
        value.to_string()
    }
}
