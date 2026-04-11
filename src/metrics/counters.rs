//! Shared atomic counters for tracking network and message metrics.
//!
//! These counters are incremented by the network layer and message router,
//! and read by the MetricsCollector to compute per-second rates
//! (spec 10-dashboard.md §6.2).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Atomic counters shared between network/router tasks and the metrics collector.
///
/// All counters are monotonically increasing totals. The MetricsCollector
/// computes rates by sampling deltas over time intervals.
pub struct NetworkCounters {
    /// Total bytes received from peers (GossipSub + sync).
    pub bytes_in: AtomicU64,
    /// Total bytes sent to peers (GossipSub + sync).
    pub bytes_out: AtomicU64,
    /// Total messages received from peers (pre-validation).
    pub messages_received: AtomicU64,
    /// Total messages relayed to peers via GossipSub.
    pub messages_relayed: AtomicU64,
    /// Total messages stored in the database.
    pub messages_stored: AtomicU64,
    /// Total rejected messages (any reason: signature, timestamp, rate limit, payload, etc.).
    pub failed_validations: AtomicU64,
    /// Total rate-limited requests.
    pub rate_limited_requests: AtomicU64,
    /// Total PoW-required rejections (wallet needs to solve challenge first).
    pub pow_required: AtomicU64,
    /// Recent rejection reasons for dashboard display (last 50).
    pub recent_rejections: Mutex<VecDeque<RecentRejection>>,
}

/// A recent message rejection for dashboard troubleshooting.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RecentRejection {
    pub timestamp: u64,
    pub reason: String,
    pub author: String,
}

impl NetworkCounters {
    /// Create a new counter set, all initialized to zero.
    pub fn new() -> Self {
        Self {
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            messages_relayed: AtomicU64::new(0),
            messages_stored: AtomicU64::new(0),
            failed_validations: AtomicU64::new(0),
            rate_limited_requests: AtomicU64::new(0),
            pow_required: AtomicU64::new(0),
            recent_rejections: Mutex::new(VecDeque::new()),
        }
    }

    /// Add to the bytes-in counter.
    pub fn add_bytes_in(&self, bytes: u64) {
        self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add to the bytes-out counter.
    pub fn add_bytes_out(&self, bytes: u64) {
        self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment the messages-received counter.
    pub fn inc_messages_received(&self) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the messages-relayed counter.
    pub fn inc_messages_relayed(&self) {
        self.messages_relayed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the messages-stored counter.
    pub fn inc_messages_stored(&self) {
        self.messages_stored.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the failed-validations counter.
    pub fn inc_failed_validations(&self) {
        self.failed_validations.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the rate-limited counter.
    pub fn inc_rate_limited(&self) {
        self.rate_limited_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the PoW-required counter.
    pub fn inc_pow_required(&self) {
        self.pow_required.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rejection with reason for dashboard display.
    pub fn record_rejection(&self, reason: &str, author: &str) {
        let entry = RecentRejection {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            reason: reason.chars().take(200).collect(),
            author: author.chars().take(66).collect(),
        };
        if let Ok(mut log) = self.recent_rejections.lock() {
            log.push_back(entry);
            while log.len() > 50 {
                log.pop_front();
            }
        }
    }

    /// Get recent rejections for dashboard display.
    pub fn get_recent_rejections(&self) -> Vec<RecentRejection> {
        self.recent_rejections
            .lock()
            .map(|log| log.iter().rev().take(20).cloned().collect())
            .unwrap_or_default()
    }

    /// Read all counters as a snapshot (for delta computation).
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            messages_relayed: self.messages_relayed.load(Ordering::Relaxed),
            messages_stored: self.messages_stored.load(Ordering::Relaxed),
            failed_validations: self.failed_validations.load(Ordering::Relaxed),
            rate_limited_requests: self.rate_limited_requests.load(Ordering::Relaxed),
            pow_required: self.pow_required.load(Ordering::Relaxed),
        }
    }
}

impl Default for NetworkCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// A point-in-time snapshot of all counter values.
///
/// Used to compute deltas between two time points for rate calculations.
#[derive(Debug, Clone, Copy, Default)]
pub struct CounterSnapshot {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub messages_received: u64,
    pub messages_relayed: u64,
    pub messages_stored: u64,
    pub failed_validations: u64,
    pub rate_limited_requests: u64,
    pub pow_required: u64,
}

impl CounterSnapshot {
    /// Compute per-second rates from the delta between this and a previous snapshot.
    pub fn rates_since(&self, prev: &CounterSnapshot, elapsed_secs: f64) -> CounterRates {
        if elapsed_secs <= 0.0 {
            return CounterRates::default();
        }
        CounterRates {
            bytes_in_per_sec: (self.bytes_in.saturating_sub(prev.bytes_in)) as f64 / elapsed_secs,
            bytes_out_per_sec: (self.bytes_out.saturating_sub(prev.bytes_out)) as f64
                / elapsed_secs,
            messages_received_per_sec: (self.messages_received.saturating_sub(prev.messages_received))
                as f64 / elapsed_secs,
            messages_relayed_per_sec: (self.messages_relayed.saturating_sub(prev.messages_relayed))
                as f64 / elapsed_secs,
            messages_stored_per_sec: (self.messages_stored.saturating_sub(prev.messages_stored))
                as f64 / elapsed_secs,
        }
    }
}

/// Per-second rates computed from counter deltas.
#[derive(Debug, Clone, Copy, Default)]
pub struct CounterRates {
    pub bytes_in_per_sec: f64,
    pub bytes_out_per_sec: f64,
    pub messages_received_per_sec: f64,
    pub messages_relayed_per_sec: f64,
    pub messages_stored_per_sec: f64,
}
