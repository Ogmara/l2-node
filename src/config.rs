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
    pub logging: LoggingConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
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
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dashboard: true,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushGatewayConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub auth_token: String,
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
            thresholds: AlertThresholds::default(),
            cooldown: AlertCooldown::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelegramAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Loaded from environment variable in production.
    #[serde(default)]
    pub bot_token: String,
    #[serde(default)]
    pub chat_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiscordAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Loaded from environment variable in production.
    #[serde(default)]
    pub webhook_url: String,
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

[logging]
level = "info"
format = "json"
"#
        .to_string()
    }
}
