//! Configuration loading and validation for the Ogmara L2 node.
//!
//! Loads from `ogmara.toml` (spec section 5). All Klever URLs are user-configured,
//! never hardcoded. Secrets (API tokens, webhook URLs) come from environment variables.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
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
    pub snapshot: SnapshotConfig,
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
    /// Bootstrap node multiaddresses for peer discovery.
    #[serde(default = "default_bootstrap_nodes")]
    pub bootstrap_nodes: Vec<String>,
    /// Maximum peer connections.
    #[serde(default = "default_max_peers")]
    pub max_peers: u32,
    /// Enable mDNS for local peer discovery.
    #[serde(default = "default_true")]
    pub enable_mdns: bool,
    /// Network identifier for peer isolation ("mainnet" or "testnet").
    /// Nodes on different networks will refuse to peer with each other.
    /// If not set, auto-detected from klever.node_url at startup.
    #[serde(default)]
    pub network_id: Option<String>,
    /// On-chain peer-discovery tuning (spec 13 §7). Added in v0.45.0.
    #[serde(default)]
    pub discovery: DiscoveryConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: default_listen_port(),
            bootstrap_nodes: default_bootstrap_nodes(),
            max_peers: default_max_peers(),
            enable_mdns: true,
            network_id: None,
            discovery: DiscoveryConfig::default(),
        }
    }
}

/// On-chain peer-discovery tuning. All fields are optional with
/// spec-aligned defaults; operators only need to override for local
/// deployments or unusually-tight networks.
///
/// Reference: [docs/specs/13-node-discovery.md §7](../../docs/specs/13-node-discovery.md#7-client-side-filtering-rules).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Drop dial-candidate peers whose on-chain `lastAnchorAt` is
    /// older than this many days. Default 7 (spec 13 §7). Local
    /// dev/test deployments may want a longer threshold; production-
    /// facing nodes should stick with the default.
    #[serde(default = "default_max_peer_staleness_days")]
    pub max_peer_staleness_days: u32,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            max_peer_staleness_days: default_max_peer_staleness_days(),
        }
    }
}

fn default_max_peer_staleness_days() -> u32 {
    7
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
    /// Block height to start scanning from (skip blocks before SC deployment).
    /// Only used when the chain cursor is 0 (fresh node). Ignored if the node
    /// has already scanned past this block. Default: 0 (scan from genesis).
    #[serde(default)]
    pub start_block: u64,
}

impl Default for KleverConfig {
    fn default() -> Self {
        Self {
            node_url: String::new(),
            api_url: String::new(),
            contract_address: String::new(),
            scan_interval_ms: default_scan_interval(),
            start_block: 0,
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
    /// Total bytes (in MiB) the media LRU cache may hold across all
    /// entries (spec 4.1, v0.40 tunable). 256 MiB default — fits a few
    /// thousand small thumbnails or a few hundred reasonable images.
    /// Raise for high-readership nodes; lower on small VMs.
    #[serde(default = "default_media_cache_total_mb")]
    pub media_cache_total_mb: u64,
    /// Per-item cap (in MiB) for the media cache. Items larger than
    /// this are never inserted (large videos stream from IPFS instead).
    /// 16 MiB default. Should be smaller than
    /// `media_cache_total_mb` and `max_upload_size_mb`.
    #[serde(default = "default_media_cache_item_mb")]
    pub media_cache_item_mb: u64,
    /// Max concurrent in-flight `/api/v1/media/:cid` handlers. Caps
    /// peak transient RSS from the media endpoint at roughly
    /// `permits * max_upload_size_mb` MiB. Default 32. Lower for
    /// resource-constrained nodes; raise for high-throughput.
    #[serde(default = "default_media_handler_permits")]
    pub media_handler_permits: usize,
    /// Per-client-IP sub-cap on concurrent media handlers (v0.41).
    /// Stops a single IP from grabbing all `media_handler_permits`
    /// slots with slow requests and starving other clients. Defaults
    /// to 4 of the 32 global permits — generous enough that a real
    /// browser opening multiple tabs is fine, tight enough that one
    /// IP can never monopolize the endpoint. Must be > 0 and
    /// <= `media_handler_permits` (validated at config-load).
    #[serde(default = "default_media_per_ip_permits")]
    pub media_per_ip_permits: usize,
    /// Hard cap on the per-IP limiter's tracking map (v0.42).
    /// Bounds memory growth under an adversarial /24-rotation flood
    /// — an attacker burning through millions of source subnets in
    /// the 5 minutes between background sweeps would otherwise
    /// inflate the DashMap to hundreds of MB. At this cap, the
    /// limiter first runs an inline sweep; if still full, new
    /// (untracked) buckets get 503 Service Unavailable until the map
    /// drains. Existing buckets continue normally — legitimate
    /// clients are never displaced. Default 65,536 ≈ 10 MiB resident.
    #[serde(default = "default_media_max_tracked_ips")]
    pub media_max_tracked_ips: usize,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            api_url: default_ipfs_api(),
            gateway_url: default_ipfs_gateway(),
            max_upload_size_mb: default_max_upload(),
            auto_thumbnail: true,
            media_cache_total_mb: default_media_cache_total_mb(),
            media_cache_item_mb: default_media_cache_item_mb(),
            media_handler_permits: default_media_handler_permits(),
            media_per_ip_permits: default_media_per_ip_permits(),
            media_max_tracked_ips: default_media_max_tracked_ips(),
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
    /// Trusted-proxy CIDRs for client-IP resolution (v0.42).
    ///
    /// When the immediate TCP peer matches one of these CIDRs (or is
    /// loopback, which is always implicitly trusted), the node walks
    /// the `Forwarded` / `X-Forwarded-For` header right-to-left,
    /// skipping addresses that are themselves trusted proxies, and
    /// reports the first untrusted address as the real client.
    ///
    /// Each entry is a CIDR string (`"10.0.0.0/8"`,
    /// `"2001:db8::/32"`) or a bare host address (`"192.0.2.5"`,
    /// `"::1"`). Validated at config-load; a malformed entry aborts
    /// startup rather than silently degrade to "trust nothing extra"
    /// (which would change the security model from "behaves as
    /// configured" to "behaves as misconfigured").
    ///
    /// Leave empty for the default single-host setup (Apache on
    /// loopback in front of L2). Add CDN/edge ranges for multi-hop
    /// CDN deployments where forwarding-header trust must extend
    /// past the immediate proxy.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Proof-of-Work anti-spam configuration.
    #[serde(default)]
    pub pow: PowConfig,
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
            trusted_proxies: Vec::new(),
            pow: PowConfig::default(),
            admin: AdminConfig::default(),
        }
    }
}

/// Proof-of-Work anti-spam configuration.
///
/// New wallets must solve a SHA-256 hash puzzle before their first message
/// is accepted. On-chain registered wallets and wallets that already solved
/// a challenge are exempt. The difficulty is measured in leading zero bits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowConfig {
    /// Enable PoW challenges for unknown wallets.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Difficulty: number of leading zero bits required in the hash.
    /// 20 bits ≈ ~1M hashes ≈ 2-3 seconds on a phone.
    #[serde(default = "default_pow_difficulty")]
    pub difficulty: u8,
    /// Challenge TTL in seconds (default: 300 = 5 minutes).
    #[serde(default = "default_pow_ttl")]
    pub challenge_ttl_seconds: u64,
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            difficulty: default_pow_difficulty(),
            challenge_ttl_seconds: default_pow_ttl(),
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
    /// If absent (or empty string), uses the node's identity key. The
    /// corresponding klv1... address must be registered on the smart contract
    /// via `registerNode` (spec 12 §2.3).
    ///
    /// **Security:** Prefer the `OGMARA_ANCHOR_WALLET_KEY` environment variable
    /// over putting the key in the config file. The key must be on-disk if
    /// `pause_on_shutdown = true` — the SIGTERM handler signs `pauseNode` from
    /// this key without operator interaction.
    ///
    /// **Residency:** the field is wrapped in [`secrecy::SecretString`] so the
    /// hex-string source is zeroized on drop and redacted by `Debug` /
    /// log-formatting paths. `Serialize` is intentionally skipped — the field
    /// must never round-trip through any config-dump output. Consumers reach
    /// the inner `&str` via [`SecretString::expose_secret`] at the two
    /// signing-key derivation callsites only (v0.46.0 Phase C / plan C1).
    /// Empty-string TOML values deserialize to `None`, mirroring pre-0.46.0
    /// behavior where empty meant absent.
    #[serde(default, deserialize_with = "deserialize_wallet_key", skip_serializing)]
    pub wallet_key: Option<SecretString>,
    /// v0.45.0 (spec 13 §6.3): if `true`, the SIGTERM handler signs and
    /// broadcasts a `pauseNode` TX before exit, signaling to other
    /// nodes + clients that this anchorer is going offline gracefully.
    /// Requires `wallet_key` set (env or config) — otherwise the
    /// handler logs a warn and exits without pausing.
    ///
    /// Default false. Enabling this is opt-in because it broadens the
    /// wallet-key threat surface: instead of the key only being used
    /// once-per-hour by the anchoring loop, it's also held in process
    /// memory for shutdown signing. See spec 13 §6.3 wallet-safety
    /// note + the v0.45.0 security audit.
    ///
    /// **Restart required for changes:** this flag is read once at
    /// node startup and cloned into `AppState`. Toggling it in the
    /// config file (and sending SIGHUP, or relying on any reload
    /// flow) does NOT update the in-process value — the SIGTERM
    /// handler continues to use whatever was set when the process
    /// started. Operators must restart the node for a change to
    /// take effect. v0.46.0 Phase B3 surfaces this as a banner in
    /// the dashboard Pause card; the live-reload refactor is
    /// deliberately out-of-scope (plan OPEN 3 resolution 2026-05-17).
    #[serde(default)]
    pub pause_on_shutdown: bool,
    /// v0.45.0 (spec 12 §2.10): optional metadata publication for
    /// on-chain peer discovery (spec 13 §4.3 / §6.1).
    #[serde(default)]
    pub metadata: AnchorMetadataConfig,
}

impl std::fmt::Debug for AnchoringConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `<configured>` rather than `<redacted>` — distinguishes
        // "operator set the field, value hidden" from `<none>` ("field
        // absent, no key configured"). The wrapped `SecretString`'s own
        // Debug impl is also redacting, but we keep the manual line for
        // a uniform two-state representation.
        f.debug_struct("AnchoringConfig")
            .field("enabled", &self.enabled)
            .field("interval_seconds", &self.interval_seconds)
            .field(
                "wallet_key",
                &if self.wallet_key.is_some() { "<configured>" } else { "<none>" },
            )
            .field("pause_on_shutdown", &self.pause_on_shutdown)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl Default for AnchoringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_seconds: default_anchor_interval(),
            wallet_key: None,
            pause_on_shutdown: false,
            metadata: AnchorMetadataConfig::default(),
        }
    }
}

/// Field-level custom deserializer for `AnchoringConfig.wallet_key`.
/// Accepts a TOML string; empty string maps to `None` (preserves the
/// pre-0.46.0 contract where `wallet_key = ""` and an absent field
/// both meant "use the node identity key"); non-empty wraps in
/// `SecretString` so the source is zeroized on drop.
///
/// The `#[serde(default)]` on the field handles the absent-field case
/// without invoking this function; this is only called when TOML
/// actually contains `wallet_key = "..."`.
///
/// **Residency note (Phase C Security Audit N1):** between the
/// `String::deserialize` call and `SecretString::from(s)` consuming
/// the owned `String`, the hex value briefly lives in a plain heap
/// allocation. `SecretString::from(String)` calls `into_boxed_str()`
/// which reuses the allocation when `capacity == len` but reallocates
/// + copies otherwise — the discarded allocation is freed without
/// zeroize. The window is brief and the threat model already assumes
/// config-file confidentiality on disk (an attacker with heap-residue
/// access typically also has the config), so we accept this gap. The
/// env-var path in `Node::run` has the same property by construction.
fn deserialize_wallet_key<'de, D>(deserializer: D) -> Result<Option<SecretString>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(if s.is_empty() {
        None
    } else {
        Some(SecretString::from(s))
    })
}

/// Convenience accessor — returns `Some(&str)` for the hex-encoded key
/// when configured, `None` when absent. Crosses the `ExposeSecret`
/// boundary so callers don't need to handle the `secrecy` type
/// directly. The returned `&str` borrows from the `SecretString`'s
/// internal `Box<str>` and lives for the lifetime of the `AnchoringConfig`
/// reference.
impl AnchoringConfig {
    pub fn wallet_key_hex(&self) -> Option<&str> {
        self.wallet_key.as_ref().map(|s| s.expose_secret())
    }
}

/// Optional on-chain metadata publication for the anchorer wallet
/// (spec 12 §2.10 `setNodeMetadata`).
///
/// Opt-in (`publish = false` by default) because spec 13 §6.2 treats
/// non-publication as a first-class operator profile — operators can
/// register + anchor without ever appearing in `getActiveNodes` for
/// privacy / regulatory-resilience reasons.
///
/// When `publish = true` and `multiaddrs = []`, the node auto-derives
/// a multiaddr from `[network] listen_port` + `[api] public_url` so
/// the operator doesn't have to hand-construct the string. Operators
/// with non-trivial topology (NAT, anonymizer front, onion) set
/// `multiaddrs` explicitly instead.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnchorMetadataConfig {
    /// Opt-in flag. Default false — node anchors silently without
    /// appearing in `getActiveNodes`.
    #[serde(default)]
    pub publish: bool,
    /// Explicit multiaddr list (≤ 8 entries, each ≤ 256 bytes per
    /// SC caps). When empty AND `publish = true`, the node
    /// auto-derives a single multiaddr from `[api] public_url`.
    #[serde(default)]
    pub multiaddrs: Vec<String>,
}

/// Snapshot bootstrap configuration (spec 11-snapshot-sync.md).
///
/// Controls peer-to-peer state snapshots: a serving node periodically caches
/// a Merkle-rooted summary of its SC-derived state (users, channels, anchors)
/// so new nodes can bootstrap without scanning millions of Klever blocks.
///
/// **Phase 1 (v0.34):** serve-only — caches a manifest and serves chunks on request.
/// **Phase 2 (v0.35):** opt-in client fetch + quorum + apply path.
/// **Phase 3 (v0.36):** anchor re-verification against Klever; default-on bootstrap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    // --- Serving (Phase 1+) ---
    /// Whether this node advertises and serves snapshots to peers.
    /// Disable on resource-constrained nodes to skip the periodic cache build.
    #[serde(default = "default_true")]
    pub serve_enabled: bool,
    /// How often to rebuild the cached snapshot from live storage (seconds).
    /// 3600 = once per hour. Lower values are wasteful; higher values mean
    /// fresh joiners replay more blocks after applying the snapshot.
    #[serde(default = "default_snapshot_rebuild_interval")]
    pub serve_rebuild_interval_secs: u64,
    /// Target chunk size in bytes for the per-CF byte stream (default 4 MiB).
    /// Smaller chunks = more parallelism but more overhead; larger = fewer
    /// requests but heavier failure-retry cost.
    #[serde(default = "default_snapshot_chunk_size")]
    pub chunk_size_bytes: u32,
    /// Maximum in-flight chunk responses across all peers. Throttles outbound
    /// bandwidth when many peers are simultaneously bootstrapping.
    #[serde(default = "default_snapshot_max_concurrent")]
    pub serve_max_concurrent_requests: u32,

    // --- Bootstrap / receive (Phase 2+) ---
    /// Whether to fetch a snapshot at startup if conditions are met.
    /// **Defaults to `true` in v0.36+** — Phase 3 added anchor
    /// re-verification against Klever AND producer signature
    /// verification, making the apply path safe to run by default on
    /// fresh nodes. Set to `false` to keep the legacy block-by-block
    /// scan from `start_block`.
    #[serde(default = "default_true")]
    pub bootstrap_enabled: bool,
    /// Only attempt bootstrap when the chain cursor is "fresh" — either zero,
    /// or below the configured `klever.start_block`. Prevents accidentally
    /// rewriting a healthy node's state if `bootstrap_enabled` is flipped on.
    #[serde(default = "default_true")]
    pub bootstrap_only_if_fresh: bool,
    /// Permit applying a snapshot onto a non-empty node (i.e., not fresh
    /// per `bootstrap_only_if_fresh`). Dangerous — the apply path clears
    /// snapshot-domain CFs before writing chunks. Default false.
    #[serde(default)]
    pub allow_apply_over_existing: bool,
    /// Total peers to sample for snapshot quorum.
    #[serde(default = "default_snapshot_quorum_sample")]
    pub quorum_sample_size: u32,
    /// Minimum peers that must agree on the snapshot root before accepting.
    #[serde(default = "default_snapshot_quorum_min")]
    pub quorum_min_peers: u32,
    /// Number of mirrors to fetch chunks from in parallel (clamped to the
    /// number of agreeing peers actually available).
    #[serde(default = "default_snapshot_parallel_fetches")]
    pub parallel_fetches: u32,
    /// Per-chunk retry budget across all mirrors before aborting bootstrap.
    #[serde(default = "default_snapshot_chunk_retries")]
    pub chunk_retries: u32,
    /// How long to wait for snapshot-capable peers before giving up
    /// and falling back to a full chain scan (seconds).
    #[serde(default = "default_snapshot_discovery_timeout")]
    pub discovery_timeout_secs: u64,
    /// Per-request timeout for `Advertise` and `GetManifest` (seconds).
    #[serde(default = "default_snapshot_manifest_timeout")]
    pub manifest_timeout_secs: u64,
    /// Per-request timeout for `GetChunk` (seconds).
    #[serde(default = "default_snapshot_chunk_timeout")]
    pub chunk_timeout_secs: u64,
    /// Hard cap on a single snapshot's combined uncompressed bytes
    /// (sum of `CfManifest.total_bytes`). Reject manifests beyond this.
    #[serde(default = "default_snapshot_max_total_bytes")]
    pub max_total_bytes: u64,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            serve_enabled: true,
            serve_rebuild_interval_secs: default_snapshot_rebuild_interval(),
            chunk_size_bytes: default_snapshot_chunk_size(),
            serve_max_concurrent_requests: default_snapshot_max_concurrent(),
            bootstrap_enabled: true,
            bootstrap_only_if_fresh: true,
            allow_apply_over_existing: false,
            quorum_sample_size: default_snapshot_quorum_sample(),
            quorum_min_peers: default_snapshot_quorum_min(),
            parallel_fetches: default_snapshot_parallel_fetches(),
            chunk_retries: default_snapshot_chunk_retries(),
            discovery_timeout_secs: default_snapshot_discovery_timeout(),
            manifest_timeout_secs: default_snapshot_manifest_timeout(),
            chunk_timeout_secs: default_snapshot_chunk_timeout(),
            max_total_bytes: default_snapshot_max_total_bytes(),
        }
    }
}

fn default_snapshot_rebuild_interval() -> u64 { 3600 }
fn default_snapshot_chunk_size() -> u32 { 4 * 1024 * 1024 }
fn default_snapshot_max_concurrent() -> u32 { 8 }
fn default_snapshot_quorum_sample() -> u32 { 5 }
fn default_snapshot_quorum_min() -> u32 { 3 }
fn default_snapshot_parallel_fetches() -> u32 { 3 }
fn default_snapshot_chunk_retries() -> u32 { 5 }
fn default_snapshot_discovery_timeout() -> u64 { 30 }
fn default_snapshot_manifest_timeout() -> u64 { 10 }
fn default_snapshot_chunk_timeout() -> u64 { 60 }
fn default_snapshot_max_total_bytes() -> u64 { 2 * 1024 * 1024 * 1024 } // 2 GiB

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
    /// Number of consecutive canonicalized heights at which the local
    /// computed root must differ from the on-chain canonical root
    /// before the `anchor_divergence` alert fires (spec 12 §6.1,
    /// spec 10 §9.2). Default 2 — one mismatch could be transient,
    /// two consecutive is a real divergence signal.
    #[serde(default = "default_anchor_divergence_consecutive")]
    pub anchor_divergence_consecutive: u32,
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
            anchor_divergence_consecutive: default_anchor_divergence_consecutive(),
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
fn default_bootstrap_nodes() -> Vec<String> {
    vec![
        "/dns4/node.ogmara.org/tcp/41720/p2p/12D3KooWNx9TnsmVQux3fMm6sUUe5tFdeXjECUSyDqYtYfsbt3Mo".to_string(),
        "/dns4/node.ogmara.org/udp/41720/quic-v1/p2p/12D3KooWNx9TnsmVQux3fMm6sUUe5tFdeXjECUSyDqYtYfsbt3Mo".to_string(),
    ]
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
fn default_media_cache_total_mb() -> u64 {
    256
}
fn default_media_cache_item_mb() -> u64 {
    16
}
fn default_media_handler_permits() -> usize {
    32
}
fn default_media_per_ip_permits() -> usize {
    4
}
fn default_media_max_tracked_ips() -> usize {
    65_536
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
fn default_pow_difficulty() -> u8 {
    20
}
fn default_pow_ttl() -> u64 {
    300
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
fn default_anchor_divergence_consecutive() -> u32 {
    2
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

/// Detect network ID from a Klever node URL.
///
/// Returns "testnet" if the URL contains "testnet", otherwise "mainnet".
/// This is the safe default: unknown URLs are treated as mainnet to prevent
/// testnet nodes from accidentally peering with mainnet.
fn detect_network_id(node_url: &str) -> String {
    if node_url.contains("testnet") {
        "testnet".to_string()
    } else {
        "mainnet".to_string()
    }
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut config: Config =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
        config.apply_migrations();
        config.validate()?;
        Ok(config)
    }

    /// Apply runtime migrations for configs created by older versions.
    ///
    /// This ensures existing node operators get critical defaults (like bootstrap
    /// nodes) without manually editing their config files after upgrades.
    fn apply_migrations(&mut self) {
        // Migration: populate empty bootstrap_nodes with official defaults.
        // Configs created before v0.27.2 have `bootstrap_nodes = []` which
        // prevents the node from joining the network.
        if self.network.bootstrap_nodes.is_empty() {
            tracing::info!("Config migration: adding default bootstrap nodes (empty bootstrap_nodes list)");
            self.network.bootstrap_nodes = default_bootstrap_nodes();
        }

        // Migration: auto-detect network_id from klever.node_url if not set.
        // Configs created before v0.28.0 have no network_id field.
        if self.network.network_id.is_none() {
            let detected = detect_network_id(&self.klever.node_url);
            tracing::info!(
                network_id = %detected,
                "Config migration: auto-detected network_id from klever.node_url"
            );
            self.network.network_id = Some(detected);
        }
    }

    /// Return the resolved network ID (always present after apply_migrations).
    pub fn network_id(&self) -> &str {
        self.network.network_id.as_deref().unwrap_or("mainnet")
    }

    /// Validate the configuration for consistency.
    ///
    /// Audit Phase 3 Sec W3: snapshot bootstrap (default-on in v0.36+)
    /// relies on Klever's `getStateRoot(block_height)` view for anchor
    /// re-verification — the entire trust model of the apply path. If
    /// `klever.node_url` is plain HTTP an on-path attacker can serve
    /// fabricated `getStateRoot` responses that match a poisoned
    /// snapshot. We warn (not hard-error) at config load so operators
    /// notice; a future version will refuse non-HTTPS outright.
    fn warn_if_non_https_klever_url(&self) {
        let url = self.klever.node_url.trim();
        if url.is_empty() {
            return;
        }
        // Allow localhost / 127.0.0.1 / private LAN URLs (often used in
        // dev / WireGuard setups where TLS terminates elsewhere).
        let is_local = url.starts_with("http://localhost")
            || url.starts_with("http://127.")
            || url.starts_with("http://10.")
            || url.starts_with("http://192.168.")
            || url.starts_with("http://[::1]");
        if url.starts_with("http://") && !is_local {
            tracing::warn!(
                klever_node_url = %url,
                "Snapshot bootstrap re-verifies anchors via Klever RPC. \
                 Using a non-HTTPS klever.node_url lets an on-path attacker forge \
                 getStateRoot responses that match a poisoned snapshot. \
                 Set https:// before enabling snapshot.bootstrap_enabled in production."
            );
        }
    }

    pub fn validate(&mut self) -> Result<()> {
        self.warn_if_non_https_klever_url();
        if self.network.listen_port == 0 {
            anyhow::bail!("network.listen_port must be > 0");
        }
        if self.api.listen_port == 0 {
            anyhow::bail!("api.listen_port must be > 0");
        }
        if self.api.listen_port == self.network.listen_port {
            anyhow::bail!("api.listen_port and network.listen_port must be different");
        }
        // Validate network_id if explicitly set
        if let Some(ref nid) = self.network.network_id {
            if nid != "mainnet" && nid != "testnet" {
                anyhow::bail!(
                    "network.network_id must be \"mainnet\" or \"testnet\", got \"{}\"",
                    nid
                );
            }
        }
        // Validate media-handler tunables (v0.40). Two classes of check:
        //
        //   HARD REJECTS — values that produce broken runtime behavior:
        //     * zero permits → semaphore deadlocks every request
        //     * zero cache caps → degenerate (cache that holds nothing)
        //     * absurd upper bounds → reverts the v0.39 memory
        //       amplification mitigation
        //
        //   SOFT FIXES — cross-field inconsistencies that DON'T affect
        //   correctness but indicate operator confusion:
        //     * item_mb > total_mb → every cached item evicts everything
        //     * item_mb > max_upload_mb → harmless (items > max_upload
        //       can't enter the system anyway), but suggests the
        //       operator is unaware of the implicit cap
        //
        //   v0.40.1 fix: soft cases now auto-clamp + warn instead of
        //   bailing. Pre-0.40.1 this branch hard-rejected legitimate
        //   pre-v0.40 production configs (e.g. `max_upload_size_mb = 10`
        //   combined with the default `media_cache_item_mb = 16`), which
        //   prevented upgrades. The hard rejects remain to catch values
        //   that actually break runtime.
        if self.ipfs.media_handler_permits == 0 {
            anyhow::bail!("ipfs.media_handler_permits must be > 0 (zero deadlocks the media endpoint)");
        }
        const MAX_MEDIA_PERMITS: usize = 4096;
        if self.ipfs.media_handler_permits > MAX_MEDIA_PERMITS {
            anyhow::bail!(
                "ipfs.media_handler_permits = {} exceeds the safety cap of {}",
                self.ipfs.media_handler_permits,
                MAX_MEDIA_PERMITS
            );
        }
        if self.ipfs.media_cache_total_mb == 0 {
            anyhow::bail!("ipfs.media_cache_total_mb must be > 0");
        }
        if self.ipfs.media_cache_item_mb == 0 {
            anyhow::bail!("ipfs.media_cache_item_mb must be > 0");
        }
        // Per-IP permits (v0.41). HARD reject zero (would 429
        // everyone — endpoint becomes unusable). HARD reject
        // exceeding the global permits (no sub-cap effect; values
        // larger than global silently degrade to "no per-IP cap"
        // which defeats the feature). SOFT clamp the upper bound to
        // global so a misconfigured `per_ip = 9999` with global = 32
        // doesn't fail upgrade — it just gets pulled back to 32.
        if self.ipfs.media_per_ip_permits == 0 {
            anyhow::bail!("ipfs.media_per_ip_permits must be > 0 (zero rejects every media request as 429)");
        }
        if self.ipfs.media_per_ip_permits > self.ipfs.media_handler_permits {
            eprintln!(
                "[config] ipfs.media_per_ip_permits ({}) > ipfs.media_handler_permits ({}); \
                 clamping to {} (per-IP cap can't exceed global cap).",
                self.ipfs.media_per_ip_permits,
                self.ipfs.media_handler_permits,
                self.ipfs.media_handler_permits,
            );
            self.ipfs.media_per_ip_permits = self.ipfs.media_handler_permits;
        }
        // Per-IP tracking map cap (v0.42). HARD reject zero — would
        // make every acquire from an untracked /24 fail-503 (no inline
        // sweep can save it from cap=0). HARD reject absurd ceilings
        // (>16M entries ≈ 2.4 GiB resident) — that's clearly a typo,
        // not a tuning choice. Honest ceilings live well under 1M.
        if self.ipfs.media_max_tracked_ips == 0 {
            anyhow::bail!(
                "ipfs.media_max_tracked_ips must be > 0 (zero would 503 every new client)",
            );
        }
        const MAX_TRACKED_IPS_CEILING: usize = 16_777_216; // 2^24
        if self.ipfs.media_max_tracked_ips > MAX_TRACKED_IPS_CEILING {
            anyhow::bail!(
                "ipfs.media_max_tracked_ips = {} exceeds the safety ceiling of {} entries",
                self.ipfs.media_max_tracked_ips,
                MAX_TRACKED_IPS_CEILING
            );
        }
        // 64 GiB is a generous ceiling for the total cache — beyond
        // this you're shifting the bottleneck to host memory. Configure
        // explicitly with a justification.
        const MAX_MEDIA_CACHE_TOTAL_MB: u64 = 65_536;
        if self.ipfs.media_cache_total_mb > MAX_MEDIA_CACHE_TOTAL_MB {
            anyhow::bail!(
                "ipfs.media_cache_total_mb = {} exceeds the safety cap of {} MiB",
                self.ipfs.media_cache_total_mb,
                MAX_MEDIA_CACHE_TOTAL_MB
            );
        }
        // SOFT FIXES below — auto-clamp and emit a warning rather than
        // bailing. `eprintln` is used instead of `tracing::warn` because
        // validation runs BEFORE the tracing subscriber is initialized;
        // a tracing warn would be silently dropped.
        //
        // Per-item cap larger than max upload: items that large can't
        // enter the system in the first place, so the over-spec is
        // harmless. Clamp to keep the displayed config self-consistent.
        if self.ipfs.media_cache_item_mb > self.ipfs.max_upload_size_mb {
            eprintln!(
                "[config] ipfs.media_cache_item_mb ({}) > ipfs.max_upload_size_mb ({}); \
                 clamping to {} (items larger than max_upload can't enter the system).",
                self.ipfs.media_cache_item_mb,
                self.ipfs.max_upload_size_mb,
                self.ipfs.max_upload_size_mb,
            );
            self.ipfs.media_cache_item_mb = self.ipfs.max_upload_size_mb;
        }
        // Per-item cap larger than total cache: each cached item would
        // evict every other item. Clamp so the LRU has room to keep
        // SOMETHING after each insert.
        if self.ipfs.media_cache_item_mb > self.ipfs.media_cache_total_mb {
            eprintln!(
                "[config] ipfs.media_cache_item_mb ({}) > ipfs.media_cache_total_mb ({}); \
                 clamping to {} (cap per item must fit within total cache).",
                self.ipfs.media_cache_item_mb,
                self.ipfs.media_cache_total_mb,
                self.ipfs.media_cache_total_mb,
            );
            self.ipfs.media_cache_item_mb = self.ipfs.media_cache_total_mb;
        }
        // Trusted-proxy CIDRs (v0.42). Parse-validate each entry at
        // load time; HARD reject on first malformed entry. Silently
        // dropping a bad CIDR would flip the security model: an
        // operator who typo'd "10.0.0/8" expecting it to cover
        // "10.0.0.0/8" would have the immediate peer NOT trusted —
        // requests from their proxy would return the proxy IP, not
        // the real client, which the operator wouldn't notice until
        // their rate-limit metrics looked off.
        for (idx, entry) in self.api.trusted_proxies.iter().enumerate() {
            crate::trusted_proxies::TrustedProxy::parse(entry).with_context(|| {
                format!("api.trusted_proxies[{}] = {:?}", idx, entry)
            })?;
        }
        Ok(())
    }

    /// Generate a default configuration file content.
    pub fn default_toml() -> String {
        r#"[node]
data_dir = "./data"

[network]
listen_port = 41720
# Official Ogmara bootstrap nodes — required for peer discovery.
# New nodes must connect to at least one bootstrap node to join the network.
bootstrap_nodes = [
    "/dns4/node.ogmara.org/tcp/41720/p2p/12D3KooWNx9TnsmVQux3fMm6sUUe5tFdeXjECUSyDqYtYfsbt3Mo",
    "/dns4/node.ogmara.org/udp/41720/quic-v1/p2p/12D3KooWNx9TnsmVQux3fMm6sUUe5tFdeXjECUSyDqYtYfsbt3Mo",
]
max_peers = 50
enable_mdns = true
# Network isolation: auto-detected from klever.node_url if not set.
# Valid values: "testnet", "mainnet".
# network_id = "testnet"

[network.discovery]
# Drop dial-candidate peers whose on-chain `lastAnchorAt` is older than
# this many days (spec 13 §7). Tier 3 (SC registry) entries only; tier
# 1 (peer book) and tier 2 (config bootstrap) carry no anchor timestamp.
# Default 7. Local-only dev deployments may want a longer threshold;
# production nodes should stick with the default.
max_peer_staleness_days = 7

[klever]
node_url = ""
api_url = ""
contract_address = ""
scan_interval_ms = 3000
# Skip blocks before SC deployment (saves hours on first sync).
# Only used when chain cursor is 0 (fresh node). Ignored once scanning has started.
# Mainnet: 29686185, Testnet: 9100000
start_block = 0

[ipfs]
api_url = "http://127.0.0.1:5001"
gateway_url = "http://127.0.0.1:8080"
max_upload_size_mb = 50
auto_thumbnail = true
# Media handler tuning (v0.39+). All optional with sensible defaults
# for a ~4 GiB-RAM VPS. Lower for resource-constrained nodes; raise
# for high-readership deployments. See IpfsConfig field docs for the
# safety constraints (validated at config-load).
media_cache_total_mb = 256        # Total LRU weight cap
media_cache_item_mb = 16          # Per-item insert cap; larger items stream
media_handler_permits = 32        # Concurrent /api/v1/media/:cid handlers (global)
media_per_ip_permits = 4          # Per-client-IP sub-cap (must be <= handler_permits)
media_max_tracked_ips = 65536     # Hard cap on the per-IP limiter map

[api]
# Set to "0.0.0.0" to accept connections from all interfaces
listen_addr = "127.0.0.1"
listen_port = 41721
# Public URL where this node's API is reachable from the public internet
# (e.g. "https://node.example.org"). REQUIRED for:
#   - inclusion in `/api/v1/network/nodes` advertising
#   - [anchoring.metadata] auto-derive (spec 13 §6.1) to compute the
#     /dns4|/ip4|/ip6 multiaddr the SC publishes on chain
# v0.46.0 Phase D supports bracketed IPv6 (`http://[2001:db8::1]:41721`).
# public_url = "https://node.example.org"
cors_origins = ["http://localhost:*"]
rate_limit_per_ip = 100
# Trusted-proxy CIDRs for client-IP resolution behind a reverse proxy
# (v0.42). Each entry is a CIDR (`"10.0.0.0/8"`, `"2001:db8::/32"`) or
# a bare address (`"192.0.2.5"`, `"::1"`). Loopback is always implicitly
# trusted. Leave empty for single-host deployments where Apache/nginx
# sits on loopback in front of the node. Malformed entries abort startup.
# trusted_proxies = []

[api.pow]
enabled = true
difficulty = 20
challenge_ttl_seconds = 300

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
# wallet_key = ""  # optional, defaults to node identity key. Prefer
# the OGMARA_ANCHOR_WALLET_KEY env var over putting the key in the
# config file. v0.46.0 wraps this field in `secrecy::SecretString` so
# the source is zeroized on drop and redacted in logs.
# pause_on_shutdown = false  # spec 13 §6.3: if true, SIGTERM signs +
# broadcasts pauseNode before exit. Requires wallet_key set. Opt-in
# because it broadens the wallet-key threat surface (key held in
# process memory for shutdown signing, not just during the anchor loop).

[anchoring.metadata]
# On-chain peer-discovery publication (spec 12 §2.10, spec 13 §6.1).
# Opt-in — non-publishers still anchor and count toward quorum but
# do not appear in `getActiveNodes` discovery output. This is the
# first-class privacy mode per spec 13 §6.2.
publish = false
# When `publish = true` AND this list is empty, the node auto-derives
# from [api] public_url + [network] listen_port:
#   /dns4/<hostname>/tcp/<port>/p2p/<peer_id> + QUIC variant for DNS
#   /ip4/<addr>/...                              for IPv4 literals
#   /ip6/<addr>/...                              for routable IPv6 literals
# Operators with non-trivial topology (NAT, load-balancer, anonymizer,
# onion) set this explicitly. Cap: 8 entries × 256 bytes each (SC limit).
multiaddrs = []

[snapshot]
# Peer-to-peer state snapshots (spec 11-snapshot-sync.md).
# Phase 3 (v0.36): default-on. Fresh nodes fetch the snapshot from
# peers and re-verify every anchor against Klever before applying.
serve_enabled = true
serve_rebuild_interval_secs = 3600
chunk_size_bytes = 4194304            # 4 MiB
serve_max_concurrent_requests = 8

# Bootstrap client — default-on in v0.36. Fresh nodes auto-bootstrap
# from peers if a quorum agrees on a snapshot AND every anchor up to
# cutoff_height verifies against Klever's getStateRoot view function.
bootstrap_enabled = true
bootstrap_only_if_fresh = true           # Refuse to overwrite an existing node's state
allow_apply_over_existing = false        # Force operator override to apply over data

quorum_sample_size = 5
quorum_min_peers = 3
parallel_fetches = 3
chunk_retries = 5
discovery_timeout_secs = 30
manifest_timeout_secs = 10
chunk_timeout_secs = 60
max_total_bytes = 2147483648             # 2 GiB hard cap on snapshot size

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
# Anchor divergence: fire `anchor_divergence` (critical) when this many
# consecutive canonicalized heights show our local root differing from
# the on-chain canonical root (spec 12 §6.1, spec 10 §9.2). Default: 2.
anchor_divergence_consecutive = 2

# --- Alert dispatcher backends (spec 10 §9.4) -------------------------
# Each backend is independent; enable any subset. Secrets (bot_token,
# webhook_url) should be loaded from environment variables in production
# rather than written to the config file. The shipping pattern: leave
# `enabled = false` here, set the secret env var, then flip enabled to
# `true` in a deployment overlay or before container start.

[alerts.telegram]
enabled = false
# chat_id = "-100123456789"
# bot_token loaded from $TELEGRAM_BOT_TOKEN env var (preferred) —
# avoid putting the token in this file.

[alerts.discord]
enabled = false
# webhook_url loaded from $DISCORD_WEBHOOK_URL env var (preferred) —
# avoid putting the URL in this file (it grants post-as-channel rights).

[alerts.webhook]
enabled = false
# url = "https://example.org/ogmara-alert"

[logging]
level = "info"
format = "json"
"#
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a baseline `Config` for validation tests by parsing the
    /// canonical `default_toml()`. Each test mutates the fields it
    /// cares about, then calls `validate()`.
    fn baseline_config() -> Config {
        toml::from_str(&Config::default_toml()).expect("default toml parses")
    }

    // --- Hard rejects ---------------------------------------------------

    #[test]
    fn validate_rejects_zero_media_permits() {
        let mut c = baseline_config();
        c.ipfs.media_handler_permits = 0;
        let err = c.validate().expect_err("zero permits must reject");
        assert!(format!("{}", err).contains("media_handler_permits"));
    }

    #[test]
    fn validate_rejects_zero_media_cache_total() {
        let mut c = baseline_config();
        c.ipfs.media_cache_total_mb = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_media_cache_item() {
        let mut c = baseline_config();
        c.ipfs.media_cache_item_mb = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_oversized_media_cache_total() {
        let mut c = baseline_config();
        c.ipfs.media_cache_total_mb = 1_000_000; // 1 TiB — way over cap
        let err = c.validate().expect_err("oversized total must reject");
        assert!(format!("{}", err).contains("media_cache_total_mb"));
    }

    #[test]
    fn validate_rejects_oversized_permits() {
        let mut c = baseline_config();
        c.ipfs.media_handler_permits = 100_000;
        assert!(c.validate().is_err());
    }

    // --- Soft fixes (v0.40.1 regression) --------------------------------

    /// Regression: pre-0.40.1 this combination (default item_mb=16
    /// against a smaller-than-default max_upload_mb=10) caused the
    /// process to exit at startup. The fix clamps + warns instead of
    /// bailing — production nodes with pre-v0.40 configs upgrade
    /// without operator intervention.
    #[test]
    fn validate_clamps_item_to_max_upload_instead_of_failing() {
        let mut c = baseline_config();
        c.ipfs.max_upload_size_mb = 10;
        c.ipfs.media_cache_item_mb = 16; // would have been the v0.40.0 default
        c.validate().expect("must NOT bail on this combination");
        assert_eq!(
            c.ipfs.media_cache_item_mb, 10,
            "item_mb should be clamped to max_upload_mb",
        );
    }

    #[test]
    fn validate_clamps_item_to_total_when_misconfigured() {
        let mut c = baseline_config();
        c.ipfs.media_cache_total_mb = 8;
        c.ipfs.media_cache_item_mb = 100;
        c.ipfs.max_upload_size_mb = 200; // not the bottleneck this time
        c.validate().expect("must NOT bail; clamp instead");
        assert!(
            c.ipfs.media_cache_item_mb <= 8,
            "item_mb clamped via max_upload then total: got {}",
            c.ipfs.media_cache_item_mb
        );
    }

    #[test]
    fn validate_passes_defaults_unchanged() {
        // Sanity: the canonical default config from `default_toml()`
        // must pass validation without any clamping. Catches a future
        // bump to a default value that conflicts with the validation.
        let mut c = baseline_config();
        let before = c.ipfs.media_cache_item_mb;
        c.validate().expect("defaults must pass");
        assert_eq!(c.ipfs.media_cache_item_mb, before, "no clamping on defaults");
    }

    #[test]
    fn validate_passes_when_item_equals_max_upload() {
        // Boundary case — equality is allowed.
        let mut c = baseline_config();
        c.ipfs.max_upload_size_mb = 16;
        c.ipfs.media_cache_item_mb = 16;
        c.validate().expect("equality is fine");
        assert_eq!(c.ipfs.media_cache_item_mb, 16);
    }

    // --- v0.41 per-IP permit field ----------------------------------

    #[test]
    fn validate_rejects_zero_per_ip_permits() {
        let mut c = baseline_config();
        c.ipfs.media_per_ip_permits = 0;
        let err = c.validate().expect_err("zero per-IP permits must reject");
        assert!(format!("{}", err).contains("media_per_ip_permits"));
    }

    #[test]
    fn validate_clamps_per_ip_to_global_permits() {
        // Operator typo / pre-v0.41 config that explicitly set
        // per_ip = 1000. The auto-clamp lets the node still boot
        // while quietly pulling per_ip back to the global cap.
        let mut c = baseline_config();
        c.ipfs.media_handler_permits = 32;
        c.ipfs.media_per_ip_permits = 1000;
        c.validate().expect("must clamp, not bail");
        assert_eq!(c.ipfs.media_per_ip_permits, 32);
    }

    #[test]
    fn validate_passes_default_per_ip_permits() {
        // Default per-IP (4) is well below default global (32).
        let mut c = baseline_config();
        c.validate().expect("defaults pass");
        assert_eq!(c.ipfs.media_per_ip_permits, 4);
    }

    // --- v0.42 max_tracked_ips field --------------------------------

    #[test]
    fn validate_rejects_zero_max_tracked_ips() {
        let mut c = baseline_config();
        c.ipfs.media_max_tracked_ips = 0;
        let err = c.validate().expect_err("zero must reject");
        assert!(format!("{}", err).contains("media_max_tracked_ips"));
    }

    #[test]
    fn validate_rejects_oversized_max_tracked_ips() {
        let mut c = baseline_config();
        c.ipfs.media_max_tracked_ips = 100_000_000; // way over ceiling
        let err = c.validate().expect_err("oversized must reject");
        assert!(format!("{}", err).contains("media_max_tracked_ips"));
    }

    #[test]
    fn validate_passes_default_max_tracked_ips() {
        let mut c = baseline_config();
        c.validate().expect("defaults pass");
        assert_eq!(c.ipfs.media_max_tracked_ips, 65_536);
    }

    // --- v0.42 trusted_proxies field --------------------------------

    #[test]
    fn validate_accepts_empty_trusted_proxies() {
        let mut c = baseline_config();
        assert!(c.api.trusted_proxies.is_empty());
        c.validate().expect("empty list (= loopback-only) is fine");
    }

    #[test]
    fn validate_accepts_well_formed_trusted_proxies() {
        let mut c = baseline_config();
        c.api.trusted_proxies = vec![
            "10.0.0.0/8".to_string(),
            "192.168.1.5".to_string(),
            "2001:db8::/32".to_string(),
            "::1".to_string(),
        ];
        c.validate().expect("all entries parse");
    }

    #[test]
    fn validate_rejects_malformed_trusted_proxy() {
        let mut c = baseline_config();
        c.api.trusted_proxies = vec![
            "10.0.0.0/8".to_string(),
            "not-an-ip".to_string(),
        ];
        let err = c.validate().expect_err("garbage entry must reject");
        assert!(format!("{:?}", err).contains("trusted_proxies"));
    }

    #[test]
    fn validate_rejects_oversized_prefix() {
        let mut c = baseline_config();
        c.api.trusted_proxies = vec!["1.2.3.4/33".to_string()];
        assert!(c.validate().is_err());
    }

    // --- AnchoringConfig.wallet_key SecretString round-trip (v0.46.0 Phase C) ---

    #[test]
    fn wallet_key_default_is_none() {
        let cfg = AnchoringConfig::default();
        assert!(cfg.wallet_key.is_none());
        assert_eq!(cfg.wallet_key_hex(), None);
    }

    #[test]
    fn wallet_key_absent_in_toml_is_none() {
        let toml = "enabled = false\ninterval_seconds = 3600\n";
        let cfg: AnchoringConfig = toml::from_str(toml).expect("parses");
        assert!(cfg.wallet_key.is_none());
    }

    #[test]
    fn wallet_key_empty_string_in_toml_is_none() {
        // Pre-0.46.0 contract: explicit `wallet_key = ""` meant "absent".
        // The custom deserializer must preserve that for backwards compat.
        let toml = "enabled = false\ninterval_seconds = 3600\nwallet_key = \"\"\n";
        let cfg: AnchoringConfig = toml::from_str(toml).expect("parses");
        assert!(cfg.wallet_key.is_none());
        assert_eq!(cfg.wallet_key_hex(), None);
    }

    #[test]
    fn wallet_key_non_empty_string_wraps_in_secret() {
        let hex = "deadbeef".repeat(8); // 64 hex chars = 32 bytes
        let toml = format!(
            "enabled = true\ninterval_seconds = 3600\nwallet_key = \"{}\"\n",
            hex
        );
        let cfg: AnchoringConfig = toml::from_str(&toml).expect("parses");
        assert!(cfg.wallet_key.is_some());
        // expose_secret round-trips the exact string the operator put in.
        assert_eq!(cfg.wallet_key_hex(), Some(hex.as_str()));
    }

    #[test]
    fn wallet_key_debug_redacts_when_configured() {
        let hex = "ab".repeat(32);
        let toml = format!(
            "enabled = true\ninterval_seconds = 3600\nwallet_key = \"{}\"\n",
            hex
        );
        let cfg: AnchoringConfig = toml::from_str(&toml).expect("parses");
        let rendered = format!("{:?}", cfg);
        // Must NOT contain the hex string itself.
        assert!(
            !rendered.contains(&hex),
            "Debug rendering must not leak wallet_key; got: {}",
            rendered
        );
        // Must report the configured-vs-absent state.
        assert!(rendered.contains("\"<configured>\""));
    }

    #[test]
    fn wallet_key_debug_shows_none_when_absent() {
        let cfg = AnchoringConfig::default();
        let rendered = format!("{:?}", cfg);
        assert!(rendered.contains("\"<none>\""));
    }

    #[test]
    fn wallet_key_rejects_non_string_toml() {
        // `String::deserialize` rejects non-string TOML values. Guards
        // against a future refactor that swaps `String` for a more
        // permissive type (e.g., serde_json::Value) that would silently
        // accept integers or booleans (Phase C Code Audit / Security
        // Audit N4).
        let toml = "enabled = false\ninterval_seconds = 3600\nwallet_key = 42\n";
        assert!(toml::from_str::<AnchoringConfig>(toml).is_err());

        let toml = "enabled = false\ninterval_seconds = 3600\nwallet_key = true\n";
        assert!(toml::from_str::<AnchoringConfig>(toml).is_err());
    }

    #[test]
    fn wallet_key_clone_preserves_secret() {
        // `SecretString` implements `Clone`; the cloned struct must
        // expose the same secret. Both copies zeroize independently on
        // drop (verified at runtime by Drop; the test just confirms
        // semantic equality).
        let hex = "1234567890abcdef".repeat(4);
        let toml = format!(
            "enabled = true\ninterval_seconds = 3600\nwallet_key = \"{}\"\n",
            hex
        );
        let cfg: AnchoringConfig = toml::from_str(&toml).expect("parses");
        let cloned = cfg.clone();
        assert_eq!(cfg.wallet_key_hex(), cloned.wallet_key_hex());
        assert_eq!(cloned.wallet_key_hex(), Some(hex.as_str()));
    }

    // --- Config discoverability (v0.46.1) ----------------------------------
    //
    // `default_toml()` is the operator-facing surface: `ogmara-node init`
    // writes it, the docker entrypoint auto-creates it, and `ogmara.example.toml`
    // is regenerated from it. The tests below guard the discoverability
    // contract — every operator-tunable section must be visible (commented
    // or set) in the default, and the static example file must stay in sync.

    #[test]
    fn default_toml_includes_all_operator_tunable_sections() {
        let s = Config::default_toml();
        for section in &[
            "[node]",
            "[network]",
            "[network.discovery]",
            "[klever]",
            "[ipfs]",
            "[api]",
            "[api.pow]",
            "[api.admin]",
            "[storage]",
            "[cache]",
            "[push_gateway]",
            "[anchoring]",
            "[anchoring.metadata]",
            "[snapshot]",
            "[metrics]",
            "[alerts]",
            "[alerts.cooldown]",
            "[alerts.thresholds]",
            "[alerts.telegram]",
            "[alerts.discord]",
            "[alerts.webhook]",
            "[logging]",
        ] {
            assert!(
                s.contains(section),
                "default_toml must include `{}` section — operators rely on \
                 `ogmara-node init` to expose every tunable surface",
                section
            );
        }
    }

    #[test]
    fn default_toml_documents_v046_knobs() {
        // Sentinel field names that must appear (commented or set) so
        // operators using `ogmara-node init` can discover the v0.45/v0.46
        // surface area. Missing means the section header is there but
        // a critical field inside isn't.
        let s = Config::default_toml();
        for needle in &[
            "max_peer_staleness_days",   // [network.discovery]
            "public_url",                // [api] — needed by auto-derive
            "trusted_proxies",           // [api] — reverse-proxy IP resolution
            "media_cache_total_mb",      // [ipfs]
            "media_per_ip_permits",      // [ipfs] — v0.41 DoS mitigation
            "pause_on_shutdown",         // [anchoring] — spec 13 §6.3
            "publish",                   // [anchoring.metadata]
        ] {
            assert!(
                s.contains(needle),
                "default_toml must mention `{}` (commented is fine) so \
                 operators can discover the knob",
                needle
            );
        }
    }

    #[test]
    fn ogmara_example_toml_matches_default_toml() {
        // The static `ogmara.example.toml` shipped in the repo and the
        // docker image MUST stay in sync with `default_toml()` (the
        // single source of truth used by `ogmara-node init` and the
        // docker entrypoint). When this test fails after changing
        // `default_toml()`, regenerate the example file:
        //   cargo run --release -- init -o ogmara.example.toml
        let example = include_str!("../ogmara.example.toml");
        let generated = Config::default_toml();
        assert_eq!(
            example, generated,
            "ogmara.example.toml is out of sync with `Config::default_toml()`. \
             Regenerate: `cargo run --release -- init -o ogmara.example.toml`"
        );
    }
}
