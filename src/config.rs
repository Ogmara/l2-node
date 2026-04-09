//! Configuration loading and validation for the Ogmara L2 node.
//!
//! Loads from `ogmara.toml` (spec section 5). All Klever URLs are user-configured,
//! never hardcoded. Secrets (API tokens, webhook URLs) come from environment variables.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Top-level node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub klever: KleverConfig,
    #[serde(default)]
    pub ipfs: IpfsConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub push_gateway: PushGatewayConfig,
    #[serde(default)]
    pub anchoring: AnchoringConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Path to store node identity key and data.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// libp2p listen port (default: 41720).
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Bootstrap node multiaddresses.
    #[serde(default)]
    pub bootstrap_nodes: Vec<String>,
    /// Maximum peer connections.
    #[serde(default = "default_max_peers")]
    pub max_peers: u32,
    /// Enable mDNS for local peer discovery.
    #[serde(default = "default_true")]
    pub enable_mdns: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: default_listen_port(),
            bootstrap_nodes: Vec::new(),
            max_peers: default_max_peers(),
            enable_mdns: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KleverConfig {
    /// Klever node RPC URL (user-configured, not hardcoded).
    #[serde(default)]
    pub node_url: String,
    /// Klever API URL (user-configured, not hardcoded).
    #[serde(default)]
    pub api_url: String,
    /// Ogmara KApp smart contract address.
    #[serde(default)]
    pub contract_address: String,
    /// Block scan interval in milliseconds.
    #[serde(default = "default_scan_interval")]
    pub scan_interval_ms: u64,
}

impl Default for KleverConfig {
    fn default() -> Self {
        Self {
            node_url: String::new(),
            api_url: String::new(),
            contract_address: String::new(),
            scan_interval_ms: default_scan_interval(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfsConfig {
    /// IPFS HTTP API URL.
    #[serde(default = "default_ipfs_api")]
    pub api_url: String,
    /// IPFS gateway URL.
    #[serde(default = "default_ipfs_gateway")]
    pub gateway_url: String,
    /// Max upload size in MB.
    #[serde(default = "default_max_upload")]
    pub max_upload_size_mb: u64,
    /// Auto-generate thumbnails for images/videos.
    #[serde(default = "default_true")]
    pub auto_thumbnail: bool,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            api_url: default_ipfs_api(),
            gateway_url: default_ipfs_gateway(),
            max_upload_size_mb: default_max_upload(),
            auto_thumbnail: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// REST/WS API listen address.
    #[serde(default = "default_api_addr")]
    pub listen_addr: String,
    /// REST/WS API listen port (default: 41721).
    #[serde(default = "default_api_port")]
    pub listen_port: u16,
    /// Public URL where this node's API is reachable (e.g. "https://node.ogmara.org").
    /// Used to advertise this node in the network node list.
    #[serde(default)]
    pub public_url: Option<String>,
    /// CORS allowed origins.
    #[serde(default = "default_cors")]
    pub cors_origins: Vec<String>,
    /// Rate limit per IP (requests per minute).
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_ip: u32,
    /// Admin API configuration.
    #[serde(default)]
    pub admin: AdminConfig,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_api_addr(),
            listen_port: default_api_port(),
            public_url: None,
            cors_origins: default_cors(),
            rate_limit_per_ip: default_rate_limit(),
            admin: AdminConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    /// Enable admin API.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Serve built-in admin dashboard.
    #[serde(default = "default_true")]
    pub dashboard: bool,
    /// Wallet addresses authorized for remote dashboard access.
    /// Empty list = localhost-only (no auth required from localhost).
    #[serde(default)]
    pub admin_wallets: Vec<String>,
    /// Session token lifetime in hours (default: 24).
    #[serde(default = "default_24")]
    pub session_ttl_hours: u64,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dashboard: true,
            admin_wallets: Vec::new(),
            session_ttl_hours: 24,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage engine (only "rocksdb" supported).
    #[serde(default = "default_engine")]
    pub engine: String,
    /// Maximum database size in GB.
    #[serde(default = "default_max_db_size")]
    pub max_db_size_gb: u64,
    /// Channels to always keep data for.
    #[serde(default)]
    pub pinned_channels: Vec<u64>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            engine: default_engine(),
            max_db_size_gb: default_max_db_size(),
            pinned_channels: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Cache TTL in seconds (0 = no expiry).
    #[serde(default = "default_cache_ttl")]
    pub ttl_seconds: u64,
    /// Max cache size in MB.
    #[serde(default = "default_cache_size")]
    pub max_size_mb: u64,
    /// Auto-pin channels on user interaction.
    #[serde(default = "default_true")]
    pub auto_pin_on_interaction: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: default_cache_ttl(),
            max_size_mb: default_cache_size(),
            auto_pin_on_interaction: true,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PushGatewayConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: String,
    #[serde(default, skip_serializing)]
    pub auth_token: String,
}

impl std::fmt::Debug for PushGatewayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushGatewayConfig")
            .field("enabled", &self.enabled)
            .field("url", &self.url)
            .field("auth_token", &if self.auth_token.is_empty() { "<none>" } else { "<redacted>" })
            .finish()
    }
}

impl Default for PushGatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            auth_token: String::new(),
        }
    }
}

/// State anchoring configuration.
///
/// When enabled, the node periodically computes a Merkle root of L2 state
/// and submits it to the Klever blockchain via the Ogmara KApp smart contract.
#[derive(Clone, Serialize, Deserialize)]
pub struct AnchoringConfig {
    /// Enable periodic state anchoring to the Klever blockchain.
    #[serde(default)]
    pub enabled: bool,
    /// Anchoring interval in seconds (default: 3600 = ~24 anchors/day).
    #[serde(default = "default_anchor_interval")]
    pub interval_seconds: u64,
    /// Optional: hex-encoded 32-byte Ed25519 private key for the anchor wallet.
    /// If empty, uses the node's identity key. The corresponding klv1... address
    /// must be authorized on the smart contract via `authorizeAnchorer`.
    ///
    /// **Security:** Prefer using `OGMARA_ANCHOR_WALLET_KEY` environment variable
    /// instead of putting the key in the config file.
    #[serde(default, skip_serializing)]
    pub wallet_key: String,
}

impl std::fmt::Debug for AnchoringConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchoringConfig")
            .field("enabled", &self.enabled)
            .field("interval_seconds", &self.interval_seconds)
            .field("wallet_key", &if self.wallet_key.is_empty() { "<none>" } else { "<redacted>" })
            .finish()
    }
}

impl Default for AnchoringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_seconds: default_anchor_interval(),
            wallet_key: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log format: json or pretty.
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub telegram: TelegramAlertConfig,
    #[serde(default)]
    pub discord: DiscordAlertConfig,
    #[serde(default)]
    pub webhook: WebhookAlertConfig,
    /// Post alerts to an Ogmara channel using a wallet identity.
    #[serde(default)]
    pub ogmara_channel: OgmaraChannelAlertConfig,
    #[serde(default)]
    pub thresholds: AlertThresholds,
    #[serde(default)]
    pub cooldown: AlertCooldown,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            telegram: TelegramAlertConfig::default(),
            discord: DiscordAlertConfig::default(),
            webhook: WebhookAlertConfig::default(),
            ogmara_channel: OgmaraChannelAlertConfig::default(),
            thresholds: AlertThresholds::default(),
            cooldown: AlertCooldown::default(),
        }
    }
}

/// Configuration for posting alerts to an Ogmara channel (spec 10-dashboard.md §9.4).
///
/// The configured wallet must already be a member of the target channel
/// (joined via a client app before enabling this feature).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OgmaraChannelAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Target channel ID (see spec 10-dashboard.md §2.2 for retrieval).
    #[serde(default)]
    pub channel_id: u64,
    /// Klever address (klv1...) to post alerts as.
    #[serde(default)]
    pub wallet_address: String,
    /// Path to Ed25519 private key file. Prefer OGMARA_ALERT_SIGNING_KEY env var.
    #[serde(default, skip_serializing)]
    pub signing_key_path: String,
}

/// Metrics collection configuration (spec 10-dashboard.md §10.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// System metrics sampling interval in seconds.
    #[serde(default = "default_10")]
    pub system_interval_seconds: u64,
    /// IPFS metrics polling interval in seconds.
    #[serde(default = "default_30")]
    pub ipfs_interval_seconds: u64,
    /// Storage metrics polling interval in seconds.
    #[serde(default = "default_60")]
    pub storage_interval_seconds: u64,
    /// Ring buffer capacity (1-minute snapshots to retain).
    #[serde(default = "default_1440")]
    pub history_capacity: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            system_interval_seconds: 10,
            ipfs_interval_seconds: 30,
            storage_interval_seconds: 60,
            history_capacity: 1440,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct TelegramAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Loaded from environment variable in production. Never put in config file.
    #[serde(default, skip_serializing)]
    pub bot_token: String,
    #[serde(default)]
    pub chat_id: String,
}

impl std::fmt::Debug for TelegramAlertConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramAlertConfig")
            .field("enabled", &self.enabled)
            .field("bot_token", &if self.bot_token.is_empty() { "<none>" } else { "<redacted>" })
            .field("chat_id", &self.chat_id)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct DiscordAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Loaded from environment variable in production. Never put in config file.
    #[serde(default, skip_serializing)]
    pub webhook_url: String,
}

impl std::fmt::Debug for DiscordAlertConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscordAlertConfig")
            .field("enabled", &self.enabled)
            .field("webhook_url", &if self.webhook_url.is_empty() { "<none>" } else { "<redacted>" })
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebhookAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    #[serde(default = "default_60")]
    pub klever_disconnect_seconds: u64,
    #[serde(default = "default_30")]
    pub ipfs_disconnect_seconds: u64,
    #[serde(default = "default_3")]
    pub min_peers: u32,
    #[serde(default = "default_90")]
    pub max_disk_usage_percent: u8,
    #[serde(default = "default_85")]
    pub max_memory_usage_percent: u8,
    #[serde(default = "default_anchor_overdue")]
    pub anchor_overdue_multiplier: f64,
    #[serde(default = "default_100_u64")]
    pub sc_sync_max_lag_blocks: u64,
    #[serde(default = "default_100_u32")]
    pub rate_limit_alert_per_min: u32,
    #[serde(default = "default_50")]
    pub failed_sig_alert_per_min: u32,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            klever_disconnect_seconds: 60,
            ipfs_disconnect_seconds: 30,
            min_peers: 3,
            max_disk_usage_percent: 90,
            max_memory_usage_percent: 85,
            anchor_overdue_multiplier: 2.0,
            sc_sync_max_lag_blocks: 100,
            rate_limit_alert_per_min: 100,
            failed_sig_alert_per_min: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCooldown {
    /// Minimum seconds between repeated alerts of the same type.
    #[serde(default = "default_300")]
    pub seconds: u64,
}

impl Default for AlertCooldown {
    fn default() -> Self {
        Self { seconds: 300 }
    }
}

// --- Default value functions ---

fn default_listen_port() -> u16 {
    41720
}
fn default_max_peers() -> u32 {
    50
}
fn default_scan_interval() -> u64 {
    3000
}
fn default_ipfs_api() -> String {
    "http://127.0.0.1:5001".to_string()
}
fn default_ipfs_gateway() -> String {
    "http://127.0.0.1:8080".to_string()
}
fn default_max_upload() -> u64 {
    50
}
fn default_api_addr() -> String {
    "127.0.0.1".to_string()
}
fn default_api_port() -> u16 {
    41721
}
fn default_cors() -> Vec<String> {
    vec!["http://localhost:*".to_string()]
}
fn default_rate_limit() -> u32 {
    100
}
fn default_engine() -> String {
    "rocksdb".to_string()
}
fn default_max_db_size() -> u64 {
    50
}
fn default_cache_ttl() -> u64 {
    86400
}
fn default_cache_size() -> u64 {
    1024
}
fn default_anchor_interval() -> u64 {
    3600
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "json".to_string()
}
fn default_true() -> bool {
    true
}
fn default_60() -> u64 {
    60
}
fn default_30() -> u64 {
    30
}
fn default_3() -> u32 {
    3
}
fn default_90() -> u8 {
    90
}
fn default_85() -> u8 {
    85
}
fn default_anchor_overdue() -> f64 {
    2.0
}
fn default_100_u64() -> u64 {
    100
}
fn default_100_u32() -> u32 {
    100
}
fn default_50() -> u32 {
    50
}
fn default_300() -> u64 {
    300
}
fn default_10() -> u64 {
    10
}
fn default_24() -> u64 {
    24
}
fn default_1440() -> u64 {
    1440
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Config =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration for consistency.
    pub fn validate(&self) -> Result<()> {
        if self.network.listen_port == 0 {
            anyhow::bail!("network.listen_port must be > 0");
        }
        if self.api.listen_port == 0 {
            anyhow::bail!("api.listen_port must be > 0");
        }
        if self.api.listen_port == self.network.listen_port {
            anyhow::bail!("api.listen_port and network.listen_port must be different");
        }
        Ok(())
    }

    /// Generate a default configuration file content.
    pub fn default_toml() -> String {
        r#"[node]
data_dir = "./data"

[network]
listen_port = 41720
bootstrap_nodes = []
max_peers = 50
enable_mdns = true

[klever]
node_url = ""
api_url = ""
contract_address = ""
scan_interval_ms = 3000

[ipfs]
api_url = "http://127.0.0.1:5001"
gateway_url = "http://127.0.0.1:8080"
max_upload_size_mb = 50
auto_thumbnail = true

[api]
# Set to "0.0.0.0" to accept connections from all interfaces
listen_addr = "127.0.0.1"
listen_port = 41721
cors_origins = ["http://localhost:*"]
rate_limit_per_ip = 100

[api.admin]
enabled = true
dashboard = true
admin_wallets = []
session_ttl_hours = 24

[storage]
engine = "rocksdb"
max_db_size_gb = 50
pinned_channels = []

[cache]
ttl_seconds = 86400
max_size_mb = 1024
auto_pin_on_interaction = true

[push_gateway]
enabled = false
url = ""
auth_token = ""

[anchoring]
enabled = false
interval_seconds = 3600
# wallet_key = ""  # optional, defaults to node identity key

[metrics]
enabled = true
system_interval_seconds = 10
ipfs_interval_seconds = 30
storage_interval_seconds = 60
history_capacity = 1440

[alerts]
enabled = false

[alerts.cooldown]
seconds = 300

[alerts.thresholds]
min_peers = 3
max_disk_usage_percent = 90
max_memory_usage_percent = 85

[logging]
level = "info"
format = "json"
"#
        .to_string()
    }
}
