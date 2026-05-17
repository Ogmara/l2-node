//! `[anchoring.metadata]` background reconciler (spec 13 §6.1).
//!
//! Compares the node's *desired* multiaddr list (post auto-derive,
//! computed via [`crate::api::admin::compute_effective_multiaddrs`])
//! against the *on-chain* `getNodeMetadata(self)` view on startup and
//! every [`RECONCILE_INTERVAL`].
//!
//! **Detect-only.** Spec 12 §6.2 mandates no proxy signing — the node
//! never signs `setNodeMetadata` on the operator's behalf. When drift
//! is detected the reconciler:
//!   1. Writes a [`MetadataDriftSnapshot`] into shared state so the
//!      dashboard can render a yellow "On-chain metadata is out of
//!      sync — click Publish to update" banner via `/admin/node/metadata`.
//!   2. Fires the [`AlertType::MetadataDriftDetected`] info alert
//!      (cooldown bounds re-fire to ~1× per hour even though the
//!      timer cadence is hourly too).
//!
//! When the on-chain list matches the desired list — OR when the
//! operator has `publish = false` — the snapshot is cleared. The
//! reconciler only runs when both anchoring AND `[anchoring.metadata]
//! publish` are enabled at startup; toggling `publish` after the node
//! is up requires a restart (matches the cloned-once `AnchorMetadataConfig`
//! contract in `AppState`).
//!
//! Locked v0.46.0 plan resolution to OPEN 2 (2026-05-17): no
//! `auto_reconcile` flag and no second SC-signing path; the operator
//! always reconciles via the dashboard.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

use crate::api::admin::compute_effective_multiaddrs;
use crate::chain::sc_views;
use crate::config::AnchorMetadataConfig;
use crate::notifications::alerts::{AlertEvent, AlertEventSender, AlertType};

/// Steady-state cadence for the reconcile fan-out. Spec 13 §6.1: "on
/// each startup and on a 1-hour timer". The startup tick happens
/// inside [`MetadataReconciler::run`] as the first iteration of the
/// interval; subsequent ticks fire on the hour.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(3600);

/// Grace period before the first reconcile tick. Gives a freshly-
/// registered node time to complete its initial `registerNode` TX
/// confirmation before the reconciler reads `getNodeMetadata(self)` —
/// without this delay, a fresh-boot node observes empty on-chain
/// metadata, falsely flags drift, and emits a spurious alert before
/// the operator has done anything wrong (Phase A Code Audit N2).
/// 60s is well within spec 13 §6.1's "on each startup" intent.
pub const STARTUP_GRACE: Duration = Duration::from_secs(60);

/// Snapshot of the most recent drift observation written by the
/// reconciler and read by the `node_metadata` admin endpoint. `None`
/// when desired ≡ on_chain (no drift), when `publish = false`, or
/// when the on-chain view is unreachable (we don't claim drift against
/// unknown chain state — same safety pattern as the
/// `in_sync = null` branch in [`crate::api::admin::node_metadata`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataDriftSnapshot {
    /// Multiaddr list the node WOULD publish if the operator clicked
    /// Publish right now.
    pub desired: Vec<String>,
    /// Multiaddr list the SC currently holds for this anchorer.
    pub on_chain: Vec<String>,
    /// Wall-clock time of the observation, unix seconds.
    pub detected_at: u64,
}

/// Cross-task handle for the drift snapshot. Reader (admin endpoint)
/// holds a clone; writer (reconciler task) holds the same Arc.
pub type SharedMetadataDrift = Arc<RwLock<Option<MetadataDriftSnapshot>>>;

/// Construct an empty shared drift slot. Always call this at node
/// startup (even when the reconciler isn't spawned) so the admin
/// endpoint can read it unconditionally.
pub fn shared_metadata_drift() -> SharedMetadataDrift {
    Arc::new(RwLock::new(None))
}

/// Pure helper — given desired vs on-chain lists, decide whether to
/// emit a drift snapshot. Extracted from the loop so the decision can
/// be unit-tested without async/IO.
///
/// Drift is reported when:
///   - `publish = true` AND
///   - `desired` is non-empty (publish enabled but unable to derive
///     a multiaddr — typically missing peer_id — is *not* drift; the
///     `auto_derived=true, effective=[]` diagnostic in `node_metadata`
///     covers that case)  AND
///   - `desired != on_chain` (element-wise, order-sensitive — matches
///     the existing `in_sync` comparison in
///     [`crate::api::admin::node_metadata`]).
///
/// When `on_chain` is `None` (RPC failed) the function returns
/// `EvaluateOutcome::Unknown` so the caller can skip both clearing AND
/// firing — same conservative posture as the admin endpoint's
/// `in_sync = null` branch.
pub fn evaluate_drift(
    publish: bool,
    desired: &[String],
    on_chain: Option<&[String]>,
    detected_at: u64,
) -> EvaluateOutcome {
    if !publish || desired.is_empty() {
        return EvaluateOutcome::Clear;
    }
    let Some(on_chain) = on_chain else {
        return EvaluateOutcome::Unknown;
    };
    let in_sync = on_chain.len() == desired.len()
        && on_chain.iter().zip(desired.iter()).all(|(a, b)| a == b);
    if in_sync {
        EvaluateOutcome::Clear
    } else {
        EvaluateOutcome::Drift(MetadataDriftSnapshot {
            desired: desired.to_vec(),
            on_chain: on_chain.to_vec(),
            detected_at,
        })
    }
}

/// Result of [`evaluate_drift`]. The reconciler maps each variant to
/// the corresponding shared-state mutation + alert behaviour.
#[derive(Debug, PartialEq, Eq)]
pub enum EvaluateOutcome {
    /// No drift OR `publish = false` OR `desired` empty. Reconciler
    /// clears any previously-written snapshot and does not alert.
    Clear,
    /// `desired != on_chain`. Reconciler writes the snapshot and fires
    /// the alert (cooldown still applies).
    Drift(MetadataDriftSnapshot),
    /// On-chain view unreachable. Reconciler preserves the prior
    /// snapshot (if any) and does not alert.
    Unknown,
}

/// The reconciler task. One per node when anchoring + metadata-publish
/// are both enabled at startup; otherwise the node skips spawning it
/// entirely.
pub struct MetadataReconciler {
    klever_view_http: reqwest::Client,
    klever_node_url: String,
    contract_address: String,
    /// Anchorer's bech32 wallet — the `getNodeMetadata` view argument.
    node_address: String,
    metadata_config: AnchorMetadataConfig,
    network_listen_port: u16,
    network_peer_id: String,
    api_public_url: Option<String>,
    /// Writer half of the shared drift snapshot.
    drift: SharedMetadataDrift,
    /// Alert sender — `None` when alerts are disabled. Sender is
    /// cloneable; we keep a single copy here for the loop.
    alert_event_tx: Option<AlertEventSender>,
}

impl MetadataReconciler {
    /// Build a reconciler. Returns an error only if the internal HTTP
    /// client cannot be constructed (no TLS backend — extremely rare).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        klever_node_url: String,
        contract_address: String,
        node_address: String,
        metadata_config: AnchorMetadataConfig,
        network_listen_port: u16,
        network_peer_id: String,
        api_public_url: Option<String>,
        drift: SharedMetadataDrift,
        alert_event_tx: Option<AlertEventSender>,
    ) -> anyhow::Result<Self> {
        let klever_view_http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            klever_view_http,
            klever_node_url,
            contract_address,
            node_address,
            metadata_config,
            network_listen_port,
            network_peer_id,
            api_public_url,
            drift,
            alert_event_tx,
        })
    }

    /// Run the reconciler loop until shutdown. The first tick fires
    /// immediately on startup (spec 13 §6.1 "on each startup"); subsequent
    /// ticks fire every [`RECONCILE_INTERVAL`].
    pub async fn run(mut self, mut shutdown_rx: broadcast::Receiver<()>) {
        if self.klever_node_url.is_empty() || self.contract_address.is_empty() {
            warn!(
                "metadata_reconcile: klever_node_url or contract_address not set; \
                 background drift check disabled (spec 13 §6.1)"
            );
            let _ = shutdown_rx.recv().await;
            return;
        }
        if self.node_address.is_empty() {
            warn!(
                "metadata_reconcile: node_address is empty; reconciler cannot read \
                 getNodeMetadata(self) and will exit"
            );
            let _ = shutdown_rx.recv().await;
            return;
        }

        info!(
            contract = %self.contract_address,
            interval_secs = RECONCILE_INTERVAL.as_secs(),
            startup_grace_secs = STARTUP_GRACE.as_secs(),
            publish_enabled = self.metadata_config.publish,
            "metadata_reconcile started (spec 13 §6.1)"
        );

        // Startup grace before the first tick — see STARTUP_GRACE
        // doc-comment. Wrap in select so shutdown during grace cleanly
        // exits without waiting the full 60s.
        tokio::select! {
            _ = tokio::time::sleep(STARTUP_GRACE) => {}
            _ = shutdown_rx.recv() => {
                debug!("metadata_reconcile shutting down during startup grace");
                return;
            }
        }

        let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
        // Tokio's first tick fires immediately — that's now the
        // post-grace startup tick, satisfying "on each startup".
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.tick_once().await;
                }
                _ = shutdown_rx.recv() => {
                    debug!("metadata_reconcile shutting down");
                    break;
                }
            }
        }
    }

    /// One reconcile pass — public for tests in the dashboard runbook
    /// that want to force a tick. Compute desired, fetch on-chain,
    /// evaluate, update shared state + maybe alert.
    pub async fn tick_once(&mut self) {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let (desired, _auto_derived) = compute_effective_multiaddrs(
            &self.metadata_config,
            self.network_listen_port,
            self.api_public_url.as_deref(),
            &self.network_peer_id,
        );

        let on_chain = match sc_views::get_node_metadata(
            &self.klever_view_http,
            &self.klever_node_url,
            &self.contract_address,
            &self.node_address,
        )
        .await
        {
            Ok(v) => Some(v),
            Err(e) => {
                debug!(
                    error = %e,
                    "metadata_reconcile: getNodeMetadata fetch failed; preserving prior snapshot"
                );
                None
            }
        };

        let outcome = evaluate_drift(
            self.metadata_config.publish,
            &desired,
            on_chain.as_deref(),
            now_unix,
        );

        match outcome {
            EvaluateOutcome::Clear => {
                let mut w = self.drift.write().await;
                if w.is_some() {
                    info!("metadata_reconcile: on-chain metadata in sync — clearing drift snapshot");
                }
                *w = None;
            }
            EvaluateOutcome::Unknown => {
                // Preserve prior snapshot; debug-logged at fetch site.
            }
            EvaluateOutcome::Drift(snapshot) => {
                info!(
                    desired_count = snapshot.desired.len(),
                    on_chain_count = snapshot.on_chain.len(),
                    "metadata_reconcile: drift detected"
                );
                {
                    let mut w = self.drift.write().await;
                    *w = Some(snapshot.clone());
                }
                self.send_alert(&snapshot).await;
            }
        }
    }

    /// Send the `metadata_drift_detected` alert. Cooldown is enforced
    /// by the alert engine; the reconciler is allowed to send freely.
    /// `try_send` (not `send`) so a wedged engine consumer can't block
    /// the reconciler — alert backpressure is observability noise we
    /// can afford to drop.
    async fn send_alert(&self, snap: &MetadataDriftSnapshot) {
        let Some(tx) = self.alert_event_tx.as_ref() else {
            return;
        };
        let details = format!(
            "Configured multiaddrs ({} entries) differ from on-chain ({} entries). \
             Click Publish in the dashboard to reconcile.",
            snap.desired.len(),
            snap.on_chain.len()
        );
        if let Err(e) = tx
            .try_send(AlertEvent {
                alert_type: AlertType::MetadataDriftDetected,
                details,
            })
        {
            debug!(error = %e, "metadata_reconcile: alert channel full or closed; dropping");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(desired: &[&str], on_chain: &[&str], at: u64) -> MetadataDriftSnapshot {
        MetadataDriftSnapshot {
            desired: desired.iter().map(|s| s.to_string()).collect(),
            on_chain: on_chain.iter().map(|s| s.to_string()).collect(),
            detected_at: at,
        }
    }

    #[test]
    fn evaluate_drift_clears_when_publish_off() {
        let desired = vec!["/dns4/a.org/tcp/1".to_string()];
        let on_chain = vec!["/dns4/b.org/tcp/1".to_string()];
        let out = evaluate_drift(false, &desired, Some(&on_chain), 100);
        assert_eq!(out, EvaluateOutcome::Clear);
    }

    #[test]
    fn evaluate_drift_clears_when_desired_empty() {
        // publish=true but auto-derive failed — covered by the
        // `node_metadata` diagnostic, not by us.
        let out = evaluate_drift(true, &[], Some(&["/dns4/b.org/tcp/1".to_string()]), 100);
        assert_eq!(out, EvaluateOutcome::Clear);
    }

    #[test]
    fn evaluate_drift_clears_when_in_sync() {
        let v = vec!["/dns4/a.org/tcp/1".to_string()];
        let out = evaluate_drift(true, &v, Some(&v), 100);
        assert_eq!(out, EvaluateOutcome::Clear);
    }

    #[test]
    fn evaluate_drift_returns_unknown_when_on_chain_none() {
        let desired = vec!["/dns4/a.org/tcp/1".to_string()];
        let out = evaluate_drift(true, &desired, None, 100);
        assert_eq!(out, EvaluateOutcome::Unknown);
    }

    #[test]
    fn evaluate_drift_returns_snapshot_when_lists_differ() {
        let desired = vec!["/dns4/a.org/tcp/1".to_string()];
        let on_chain = vec!["/dns4/b.org/tcp/1".to_string()];
        let out = evaluate_drift(true, &desired, Some(&on_chain), 100);
        assert_eq!(out, EvaluateOutcome::Drift(snap(&["/dns4/a.org/tcp/1"], &["/dns4/b.org/tcp/1"], 100)));
    }

    #[test]
    fn evaluate_drift_is_order_sensitive() {
        // Element-wise comparison matches the existing `in_sync` rule
        // in `api/admin.rs::node_metadata`. Reordering counts as drift
        // because `setNodeMetadata` preserves operator-supplied order.
        let desired = vec!["a".to_string(), "b".to_string()];
        let on_chain = vec!["b".to_string(), "a".to_string()];
        let out = evaluate_drift(true, &desired, Some(&on_chain), 100);
        assert!(matches!(out, EvaluateOutcome::Drift(_)));
    }

    #[test]
    fn evaluate_drift_distinguishes_length_mismatch() {
        let desired = vec!["a".to_string()];
        let on_chain = vec!["a".to_string(), "b".to_string()];
        let out = evaluate_drift(true, &desired, Some(&on_chain), 100);
        assert!(matches!(out, EvaluateOutcome::Drift(_)));
    }
}
