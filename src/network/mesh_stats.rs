//! GossipSub mesh-state instrumentation (spec 10 §9.2, l2-node 0.46.6+).
//!
//! B4 in `docs/planning/mainnet-blockers-fix-plan.md` is the asymmetric
//! GossipSub propagation observed on the Odroid ↔ prod testnet pair
//! (operator's local node receives but never delivers, despite the mesh
//! showing peers on both sides). The 0.46.6 release does *not* fix B4 —
//! the fix is gated on the data this module captures. The instrumentation
//! is:
//!
//! 1. Periodically snapshot per-topic mesh size and subscriber count
//!    from `gossipsub::Behaviour` into a shared
//!    [`MeshStatsSnapshot`] read by the `/admin/network/mesh-stats`
//!    endpoint.
//! 2. Track cumulative publish-failure counters by error variant
//!    (`NoPeersSubscribedToTopic`, `AllQueuesFull`, other) via
//!    [`PublishFailureCounters`].
//! 3. Fire [`crate::notifications::alerts::AlertType::PublishFailedInsufficientPeers`]
//!    when the "no peers subscribed" case happens — gated by the
//!    standard alert cooldown so a chronically empty topic does not
//!    flood the alert log.
//!
//! Operator runbook for capturing the full GossipSub event stream
//! during diagnosis (the data this snapshot alone does not surface —
//! IHAVE / IWANT / GRAFT / PRUNE messages):
//!
//! ```text
//! RUST_LOG="info,libp2p_gossipsub=trace" ogmara-node --config ogmara.toml
//! ```
//!
//! Captures every mesh control message for 30 minutes; pair with
//! `/admin/network/mesh-stats` snapshots before and after to bracket
//! the observation window. The trace stream is very verbose (multi-
//! megabytes per minute on a busy node) — leave the filter on only
//! during active diagnosis.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use serde::Serialize;

/// Per-topic mesh state at snapshot time. One entry per subscribed
/// topic; topics with `subscribers = 0 && mesh_size = 0` are omitted
/// from the snapshot to keep dashboards focused.
#[derive(Debug, Default, Clone, Serialize)]
pub struct TopicMeshStats {
    /// GossipSub topic rendering as returned by `TopicHash::Display`.
    /// Because the Ogmara behaviour uses `IdentTopic`
    /// (`Topic<IdentityHash>`), the hash field stores the raw topic
    /// string verbatim — operators see e.g.
    /// `/ogmara/mainnet/v1/news.global` rather than a SHA-256 digest.
    /// If we switch to `Sha256Topic` in the future, the same field
    /// renders as base64(sha256(topic)) without any caller change.
    pub topic: String,
    /// Number of peers currently in our mesh for this topic. This is
    /// the count returned by
    /// [`libp2p::gossipsub::Behaviour::mesh_peers`] at snapshot time.
    pub mesh_size: usize,
    /// Number of peers known to be subscribed to this topic from the
    /// gossipsub subscriber view. Includes mesh + fanout + gossip-
    /// only peers. Population from
    /// [`libp2p::gossipsub::Behaviour::all_peers`] filtered by topic.
    pub subscribers: usize,
}

/// Shared mesh-state snapshot — produced by `NetworkService` on a
/// periodic tick, read by the `/admin/network/mesh-stats` endpoint.
#[derive(Debug, Default, Clone, Serialize)]
pub struct MeshStatsSnapshot {
    /// Unix-seconds at snapshot generation. `0` until the first tick
    /// — endpoints surface this so callers can tell "never updated"
    /// from "fresh snapshot".
    pub generated_at_unix: u64,
    /// Per-topic mesh state, sorted by topic string for stable
    /// dashboards.
    pub topics: Vec<TopicMeshStats>,
    /// Total mesh slots across all topics (with duplicates if a peer
    /// is in multiple topic meshes). Useful as a quick "is the mesh
    /// alive at all" gauge.
    pub total_mesh_slots: usize,
    /// Cumulative count of *all* failed publishes since process
    /// start. Includes the three sub-counters below plus any future
    /// `PublishError` variants we have not yet classified.
    pub publish_failures_total: u64,
    /// Subset: publishes that failed because no peer was subscribed
    /// to the target topic (B4 signature). Fires the
    /// `publish_failed_insufficient_peers` alert.
    pub publish_failures_no_peers: u64,
    /// Subset: publishes that failed because every peer's send queue
    /// was full. Distinct B-class signal — points at backpressure /
    /// slow peers rather than empty mesh.
    pub publish_failures_all_queues_full: u64,
    /// Subset: any other `PublishError` variant (`Duplicate`,
    /// `SigningError`, `MessageTooLarge`, `TransformFailed`, plus any
    /// future-added variants caught by the wildcard arm). Useful for
    /// trend visibility even though the individual variants are less
    /// directly actionable. Invariant: `publish_failures_total ==
    /// no_peers + all_queues_full + other` — every variant is counted
    /// exactly once.
    pub publish_failures_other: u64,
}

/// `Arc<RwLock>` wrapper for the snapshot — one writer (NetworkService
/// tick) and many readers (admin handler, future dashboard polls).
/// `std::sync::RwLock` (not tokio) because the snapshot is small and
/// read paths never await; lock holds are sub-millisecond.
pub type SharedMeshStats = Arc<RwLock<MeshStatsSnapshot>>;

/// Allocate a fresh empty snapshot. Used by `AppState` constructors
/// (tests + production) so the handler can read a sane default before
/// the first tick lands.
pub fn shared_empty() -> SharedMeshStats {
    Arc::new(RwLock::new(MeshStatsSnapshot::default()))
}

/// Cumulative publish-failure counters, classified by error variant.
///
/// `Arc<AtomicU64>` per field so the network task can increment in
/// the hot publish path without taking any lock, and the snapshot
/// task / admin handler can read live values without blocking the
/// publish loop. All loads / stores use `Ordering::Relaxed` —
/// counter monotonicity is the only correctness requirement; cross-
/// thread visibility lags by at most one tick which is acceptable
/// for diagnostic counters.
#[derive(Debug, Clone, Default)]
pub struct PublishFailureCounters {
    pub total: Arc<AtomicU64>,
    pub no_peers: Arc<AtomicU64>,
    pub all_queues_full: Arc<AtomicU64>,
    pub other: Arc<AtomicU64>,
}

impl PublishFailureCounters {
    /// Record one failure, incrementing `total` plus the variant-
    /// specific sub-counter. Returns `true` if the failure was a
    /// "no peers subscribed" case — caller uses this to decide
    /// whether to fire the `publish_failed_insufficient_peers`
    /// alert (cooldown deduplication happens in `AlertEngine`).
    pub fn record(&self, err: &libp2p::gossipsub::PublishError) -> bool {
        use libp2p::gossipsub::PublishError as E;
        self.total.fetch_add(1, Ordering::Relaxed);
        match err {
            E::NoPeersSubscribedToTopic => {
                self.no_peers.fetch_add(1, Ordering::Relaxed);
                true
            }
            E::AllQueuesFull(_) => {
                self.all_queues_full.fetch_add(1, Ordering::Relaxed);
                false
            }
            _ => {
                self.other.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Snapshot all four counters atomically-enough (each load is
    /// individually atomic; cross-counter consistency is not required
    /// — the snapshot is for diagnosis, not accounting).
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.total.load(Ordering::Relaxed),
            self.no_peers.load(Ordering::Relaxed),
            self.all_queues_full.load(Ordering::Relaxed),
            self.other.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::gossipsub::PublishError;

    #[test]
    fn record_no_peers_returns_true_and_bumps_counter() {
        let c = PublishFailureCounters::default();
        let fired = c.record(&PublishError::NoPeersSubscribedToTopic);
        assert!(fired, "NoPeersSubscribedToTopic must signal alert");
        let (total, no_peers, full, other) = c.snapshot();
        assert_eq!((total, no_peers, full, other), (1, 1, 0, 0));
    }

    #[test]
    fn record_all_queues_full_returns_false() {
        let c = PublishFailureCounters::default();
        let fired = c.record(&PublishError::AllQueuesFull(7));
        assert!(!fired);
        let (total, no_peers, full, other) = c.snapshot();
        assert_eq!((total, no_peers, full, other), (1, 0, 1, 0));
    }

    #[test]
    fn record_duplicate_returns_false_and_increments_other() {
        let c = PublishFailureCounters::default();
        let fired = c.record(&PublishError::Duplicate);
        assert!(!fired);
        let (total, no_peers, full, other) = c.snapshot();
        assert_eq!((total, no_peers, full, other), (1, 0, 0, 1));
    }

    #[test]
    fn counters_are_independently_atomic_under_clone() {
        // The Arc<AtomicU64> design means clones share state. Verify
        // a clone observes increments made through the original.
        let c = PublishFailureCounters::default();
        let cloned = c.clone();
        c.record(&PublishError::NoPeersSubscribedToTopic);
        cloned.record(&PublishError::NoPeersSubscribedToTopic);
        assert_eq!(c.snapshot(), (2, 2, 0, 0));
        assert_eq!(cloned.snapshot(), (2, 2, 0, 0));
    }

    #[test]
    fn shared_empty_starts_at_zero() {
        let snap = shared_empty();
        let read = snap.read().unwrap();
        assert_eq!(read.generated_at_unix, 0);
        assert!(read.topics.is_empty());
        assert_eq!(read.publish_failures_total, 0);
    }
}
