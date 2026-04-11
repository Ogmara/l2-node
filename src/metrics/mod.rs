//! Metrics collection and time-series storage for the node dashboard.
//!
//! The MetricsCollector runs as a background task, sampling system metrics,
//! network counters, storage stats, and IPFS health at configurable intervals.
//! Data is stored in a ring buffer for dashboard chart rendering
//! (spec 10-dashboard.md §4, §6).

pub mod counters;
pub mod ring_buffer;
pub mod system;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use tracing::{debug, warn};

use crate::config::MetricsConfig;
use crate::ipfs::client::IpfsClient;
use crate::storage::rocks::Storage;
use crate::storage::schema::state_keys;

use self::counters::{CounterSnapshot, NetworkCounters};
use self::ring_buffer::RingBuffer;
use self::system::SystemCollector;

/// Full metrics snapshot pushed to the dashboard every 2 seconds.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct MetricsSnapshot {
    /// Unix timestamp in milliseconds.
    pub timestamp_ms: u64,

    // System
    pub cpu_percent: f32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,

    // Network
    pub peers_connected: u32,
    pub bandwidth_in_bytes_sec: u64,
    pub bandwidth_out_bytes_sec: u64,
    pub messages_received_sec: f64,
    pub messages_relayed_sec: f64,

    // Counters (totals)
    pub messages_received_total: u64,
    pub messages_relayed_total: u64,
    pub messages_stored_total: u64,
    pub failed_validations_total: u64,
    pub rate_limited_total: u64,
    pub pow_required_total: u64,

    // Storage
    pub db_size_bytes: u64,
    pub messages_total: u64,
    pub channel_messages_total: u64,
    pub news_messages_total: u64,
    pub users_total: u64,
    pub channels_total: u64,

    // IPFS
    pub ipfs_connected: bool,
    pub ipfs_pinned_count: u64,
    pub ipfs_repo_size_bytes: u64,

    // Chain
    pub klever_last_block: u64,
    pub klever_sync_lag_blocks: u64,

    // Anchoring
    pub last_anchor_height: u64,
    pub last_anchor_age_seconds: u64,
    pub total_anchors: u64,

    // Wallet
    /// Node's KLV balance in KLV units (balance / 1_000_000 for display).
    pub wallet_balance_klv: u64,
}

/// Cached storage statistics (refreshed at storage_interval).
#[derive(Debug, Clone, Copy, Default)]
struct StorageStats {
    db_size: u64,
    messages_total: u64,
    channel_messages: u64,
    news_messages: u64,
    users_total: u64,
    channels_total: u64,
    klever_last_block: u64,
    last_anchor_ts: u64,
    total_anchors: u64,
}

/// IPFS statistics collected via the IPFS HTTP API.
#[derive(Debug, Clone, Copy, Default)]
struct IpfsStats {
    connected: bool,
    pinned_count: u64,
    repo_size_bytes: u64,
}

/// The central metrics collector.
///
/// Runs as a background tokio task, sampling metrics at configured intervals
/// and storing snapshots in a ring buffer for historical data.
pub struct MetricsCollector {
    config: MetricsConfig,
    storage: Storage,
    ipfs: Option<IpfsClient>,
    peer_count: Arc<AtomicU32>,
    counters: Arc<NetworkCounters>,
    node_id: String,
    /// Klever API URL for balance queries.
    klever_api_url: String,
    /// Node's Klever wallet address (klv1...).
    node_address: String,
    /// HTTP client for Klever API queries.
    http: reqwest::Client,

    // Internal state
    system_collector: SystemCollector,
    prev_counter_snapshot: CounterSnapshot,
    prev_counter_time: Instant,
    ipfs_stats: IpfsStats,
    wallet_balance: u64,

    // Output
    latest: Arc<RwLock<MetricsSnapshot>>,
    history: Arc<RwLock<RingBuffer<MetricsSnapshot>>>,
}

impl MetricsCollector {
    /// Create a new metrics collector.
    pub fn new(
        config: MetricsConfig,
        storage: Storage,
        ipfs: Option<IpfsClient>,
        peer_count: Arc<AtomicU32>,
        counters: Arc<NetworkCounters>,
        data_dir: &str,
        node_id: String,
        klever_api_url: String,
        node_address: String,
    ) -> Self {
        // Clamp capacity: min 60 (1 hour), max 10080 (1 week at 1-min resolution)
        let capacity = (config.history_capacity as usize).clamp(60, 10080);
        Self {
            config,
            storage,
            ipfs,
            peer_count,
            counters,
            node_id,
            klever_api_url,
            node_address,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            system_collector: SystemCollector::new(data_dir),
            prev_counter_snapshot: CounterSnapshot::default(),
            prev_counter_time: Instant::now(),
            ipfs_stats: IpfsStats::default(),
            wallet_balance: 0,
            latest: Arc::new(RwLock::new(MetricsSnapshot::default())),
            history: Arc::new(RwLock::new(RingBuffer::new(capacity))),
        }
    }

    /// Get a handle to the latest metrics snapshot (for WebSocket push).
    pub fn latest_handle(&self) -> Arc<RwLock<MetricsSnapshot>> {
        self.latest.clone()
    }

    /// Get a handle to the history ring buffer (for chart data).
    pub fn history_handle(&self) -> Arc<RwLock<RingBuffer<MetricsSnapshot>>> {
        self.history.clone()
    }

    /// Run the metrics collection loop.
    ///
    /// This should be spawned as a tokio task. It runs until the shutdown
    /// signal is received.
    pub async fn run(mut self, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
        let system_interval = Duration::from_secs(self.config.system_interval_seconds);
        let ipfs_interval = Duration::from_secs(self.config.ipfs_interval_seconds);
        let storage_interval = Duration::from_secs(self.config.storage_interval_seconds);
        let history_interval = Duration::from_secs(60); // 1-minute ring buffer writes

        let mut system_tick = tokio::time::interval(system_interval);
        let mut ipfs_tick = tokio::time::interval(ipfs_interval);
        let mut storage_tick = tokio::time::interval(storage_interval);
        let mut history_tick = tokio::time::interval(history_interval);

        // Cached storage metrics (refreshed at storage_interval)
        let mut ss = StorageStats::default();
        self.collect_storage_stats(&mut ss);

        debug!("Metrics collector started");

        loop {
            tokio::select! {
                _ = system_tick.tick() => {
                    self.system_collector.refresh_cpu_memory();
                    self.update_latest_snapshot(&ss);
                }
                _ = ipfs_tick.tick() => {
                    self.refresh_ipfs_stats().await;
                }
                _ = storage_tick.tick() => {
                    self.system_collector.refresh_disks();
                    self.collect_storage_stats(&mut ss);
                    self.refresh_wallet_balance().await;
                }
                _ = history_tick.tick() => {
                    // Write current snapshot to history ring buffer
                    if let Ok(snapshot) = self.latest.read() {
                        if let Ok(mut history) = self.history.write() {
                            history.push(*snapshot);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    debug!("Metrics collector shutting down");
                    break;
                }
            }
        }
    }

    /// Update the latest snapshot with current data from all sources.
    fn update_latest_snapshot(&mut self, ss: &StorageStats) {
        let system = self.system_collector.collect();
        let counter_snap = self.counters.snapshot();
        let elapsed = self.prev_counter_time.elapsed().as_secs_f64();
        let rates = counter_snap.rates_since(&self.prev_counter_snapshot, elapsed);
        self.prev_counter_snapshot = counter_snap;
        self.prev_counter_time = Instant::now();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let anchor_age = if ss.last_anchor_ts > 0 {
            (now_ms / 1000).saturating_sub(ss.last_anchor_ts)
        } else {
            0
        };

        let snapshot = MetricsSnapshot {
            timestamp_ms: now_ms,
            cpu_percent: system.cpu_percent,
            memory_used_bytes: system.memory_used_bytes,
            memory_total_bytes: system.memory_total_bytes,
            disk_used_bytes: system.disk_used_bytes,
            disk_total_bytes: system.disk_total_bytes,
            peers_connected: self.peer_count.load(Ordering::Relaxed),
            bandwidth_in_bytes_sec: rates.bytes_in_per_sec as u64,
            bandwidth_out_bytes_sec: rates.bytes_out_per_sec as u64,
            messages_received_sec: rates.messages_received_per_sec,
            messages_relayed_sec: rates.messages_relayed_per_sec,
            messages_received_total: counter_snap.messages_received,
            messages_relayed_total: counter_snap.messages_relayed,
            messages_stored_total: counter_snap.messages_stored,
            failed_validations_total: counter_snap.failed_validations,
            rate_limited_total: counter_snap.rate_limited_requests,
            pow_required_total: counter_snap.pow_required,
            db_size_bytes: ss.db_size,
            messages_total: ss.messages_total,
            channel_messages_total: ss.channel_messages,
            news_messages_total: ss.news_messages,
            users_total: ss.users_total,
            channels_total: ss.channels_total,
            ipfs_connected: self.ipfs_stats.connected,
            ipfs_pinned_count: self.ipfs_stats.pinned_count,
            ipfs_repo_size_bytes: self.ipfs_stats.repo_size_bytes,
            klever_last_block: ss.klever_last_block,
            klever_sync_lag_blocks: {
                let chain_tip = self.storage.get_stat(state_keys::CHAIN_TIP).unwrap_or(0);
                chain_tip.saturating_sub(ss.klever_last_block)
            },
            last_anchor_height: 0,
            last_anchor_age_seconds: anchor_age,
            total_anchors: ss.total_anchors,
            wallet_balance_klv: self.wallet_balance,
        };

        if let Ok(mut latest) = self.latest.write() {
            *latest = snapshot;
        }
    }

    /// Collect storage statistics from RocksDB and NODE_STATE counters.
    fn collect_storage_stats(&self, ss: &mut StorageStats) {
        ss.messages_total = self.storage.get_stat(state_keys::TOTAL_MESSAGES).unwrap_or(0);
        ss.channel_messages = self.storage.get_stat(state_keys::TOTAL_CHANNEL_MESSAGES).unwrap_or(0);
        ss.news_messages = self.storage.get_stat(state_keys::TOTAL_NEWS_MESSAGES).unwrap_or(0);
        ss.users_total = self.storage.get_stat(state_keys::TOTAL_USERS).unwrap_or(0);
        ss.channels_total = self.storage.get_stat(state_keys::TOTAL_CHANNELS).unwrap_or(0);
        ss.klever_last_block = self.storage.get_chain_cursor().unwrap_or(0);
        ss.last_anchor_ts = self.storage.get_stat(state_keys::LAST_ANCHOR_TS).unwrap_or(0);

        // Get anchor status from ANCHOR_BY_NODE CF (accurate for this node)
        match self.storage.get_self_anchor_status(&self.node_id) {
            Ok(status) => ss.total_anchors = status.total_anchors,
            Err(_) => ss.total_anchors = 0,
        }

        // Estimate database size from RocksDB properties
        ss.db_size = self.storage.estimate_db_size().unwrap_or(0);
    }

    /// Refresh IPFS health and stats.
    async fn refresh_ipfs_stats(&mut self) {
        let Some(ref ipfs) = self.ipfs else {
            self.ipfs_stats = IpfsStats::default();
            return;
        };

        // Health check
        match ipfs.health_check().await {
            Ok(healthy) => self.ipfs_stats.connected = healthy,
            Err(_) => {
                self.ipfs_stats.connected = false;
                return;
            }
        }

        if !self.ipfs_stats.connected {
            return;
        }

        // Repo stats (size + pin count)
        match ipfs.repo_stat().await {
            Ok((size, count)) => {
                self.ipfs_stats.repo_size_bytes = size;
                self.ipfs_stats.pinned_count = count;
            }
            Err(e) => {
                warn!(error = %e, "Failed to collect IPFS repo stats");
            }
        }
    }

    /// Fetch the node's KLV balance from the Klever API.
    async fn refresh_wallet_balance(&mut self) {
        if self.klever_api_url.is_empty() || self.node_address.is_empty() {
            return;
        }

        let url = format!("{}/v1.0/address/{}", self.klever_api_url, self.node_address);
        match self.http.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(body) => {
                        self.wallet_balance = body
                            .pointer("/data/account/balance")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                    }
                    Err(e) => debug!(error = %e, "Failed to parse wallet balance response"),
                }
            }
            Ok(resp) if resp.status().as_u16() == 404 => {
                // Account not found on-chain (never funded)
                self.wallet_balance = 0;
            }
            _ => {} // silently skip on network errors (will retry next cycle)
        }
    }
}
