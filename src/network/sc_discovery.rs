//! SC-based peer discovery — bootstraps the L2 mesh from the on-chain
//! node registry when the persisted peer book is empty/stale OR the
//! configured `bootstrap_nodes` are unreachable.
//!
//! This is **tier 3** of the bootstrap layering per spec 13 §4. Tier 1
//! is the persisted peer book ([`super::mod::dial_persisted_peers`]),
//! tier 2 is the static `bootstrap_nodes` config, tier 4 is libp2p's
//! Kademlia DHT + mDNS at runtime. SC discovery sits between static
//! config and DHT: it's how a new node finds the network without
//! depending on any specific hardcoded seed staying online.
//!
//! Triggered:
//!   - On startup (early — within ~60s of `NetworkService::run`
//!     entering its loop) if the peer book has fewer than
//!     `BOOTSTRAP_SC_FALLBACK_BOOK_THRESHOLD` entries.
//!   - Periodically every `BOOTSTRAP_SC_REFRESH_INTERVAL` (1h) during
//!     steady-state operation to keep the persisted book in sync with
//!     operator churn (new registrations, paused nodes, unregistrations).
//!
//! Flow per run:
//!   1. Page `getActiveNodes(offset, limit)` from the SC (limit = 64,
//!      capped at `MAX_SC_DISCOVERY_TOTAL` across all pages).
//!   2. Filter each returned `(address, lastAnchorAt)` tuple:
//!      - Skip if `lastAnchorAt < (now - PEER_STALENESS_THRESHOLD)`
//!        (default 7 days per spec 13 §7).
//!      - Skip if `isNodePaused(address)` is true (defense-in-depth
//!        even though `getActiveNodes` already excludes paused).
//!      - Skip if `address == self_address` (don't dial ourselves).
//!   3. For each surviving address, fetch `getNodeMetadata(address)`
//!      and parse each entry as a libp2p [`Multiaddr`].
//!   4. Persist successfully-parsed multiaddrs to `PEER_DIRECTORY`
//!      via [`super::mod::NetworkService::persist_peer_addr`] (this
//!      is reachable through the storage handle directly — same
//!      key prefix `pa:`).
//!   5. Send a reconnect signal so `NetworkService` calls
//!      `dial_persisted_peers()` out-of-cycle (the alternative would
//!      be waiting up to 30s for the next periodic bootstrap pass).
//!   6. On the FIRST successful run that persisted at least one new
//!      multiaddr in a startup window, fire `BootstrapScFallbackUsed`
//!      (info) so the operator sees confirmation that SC discovery
//!      actually engaged.
//!
//! Rate limits: one fan-out per `BOOTSTRAP_SC_REFRESH_INTERVAL` per
//! node; per-address metadata fetches are uncached at this layer (the
//! reqwest client may have HTTP-level caching but we don't assume it).
//! At realistic scale (≤ 100 registered nodes, 1h cadence) total view-
//! call load is ≤ ~200 calls/hour, well within Klever RPC budgets.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::Multiaddr;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::chain::sc_views;
use crate::notifications::alerts::{AlertEvent, AlertEventSender, AlertType};
use crate::storage::rocks::Storage;

/// Minimum entries in the persisted peer book below which the startup
/// fan-out is triggered. Matches the spec 13 §4.3 threshold.
pub const BOOTSTRAP_SC_FALLBACK_BOOK_THRESHOLD: usize = 3;

/// Steady-state cadence for the periodic refresh fan-out.
pub const BOOTSTRAP_SC_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

/// Max addresses kept across all paginated SC pages in a single run.
/// Matches the `PEER_DIRECTORY` cap so we never persist more than the
/// book can hold.
pub const MAX_SC_DISCOVERY_TOTAL: usize = 256;

/// Filter cutoff for `lastAnchorAt` — addresses that haven't anchored
/// within this window are skipped. Matches spec 13 §7 default.
pub const PEER_STALENESS_THRESHOLD: Duration = Duration::from_secs(7 * 24 * 3600);

/// Page size for `getActiveNodes` — must match the SC's
/// `GET_ACTIVE_NODES_MAX_LIMIT = 64`.
const PAGE_SIZE: u32 = 64;

/// Key prefix for persisted peer addresses in `PEER_DIRECTORY`.
/// **Must match** `NetworkService::PEER_ADDR_PREFIX` — keep these two
/// constants in sync. The two callers (NetworkService::persist and
/// sc_discovery::persist below) write to the same key space so the
/// existing dial_persisted_peers() path picks up both sources
/// uniformly.
const PEER_ADDR_PREFIX: &[u8] = b"pa:";

/// SC-based peer discovery task. Owns the SC view-call surface and
/// the storage write path; communicates with `NetworkService` only
/// via the reconnect-trigger channel.
pub struct ScDiscovery {
    klever_node_url: String,
    contract_address: String,
    http: reqwest::Client,
    storage: Storage,
    /// Our own anchorer address (bech32 klv1...) — excluded from
    /// dial candidates.
    self_address: String,
    /// Send a `()` here whenever new multiaddrs have been persisted,
    /// signaling `NetworkService` to call `dial_persisted_peers()`
    /// out-of-cycle.
    reconnect_trigger_tx: mpsc::Sender<()>,
    /// Optional alert sender. `None` when alerts are disabled.
    alert_event_tx: Option<AlertEventSender>,
    /// Has the `BootstrapScFallbackUsed` alert fired for THIS process
    /// startup window? Reset on process restart only. One-shot per
    /// startup keeps the alert from spamming once steady-state
    /// operation kicks in.
    fallback_alert_fired: bool,
}

impl ScDiscovery {
    pub fn new(
        klever_node_url: String,
        contract_address: String,
        storage: Storage,
        self_address: String,
        reconnect_trigger_tx: mpsc::Sender<()>,
        alert_event_tx: Option<AlertEventSender>,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            klever_node_url,
            contract_address,
            http,
            storage,
            self_address,
            reconnect_trigger_tx,
            alert_event_tx,
            fallback_alert_fired: false,
        })
    }

    /// Run the sc_discovery loop until shutdown. Returns when the
    /// shutdown channel fires.
    pub async fn run(mut self, mut shutdown_rx: broadcast::Receiver<()>) {
        if self.klever_node_url.is_empty() || self.contract_address.is_empty() {
            warn!(
                "sc_discovery: klever_node_url or contract_address not set; \
                 SC peer discovery disabled (tier 3 of spec 13 §4.3)"
            );
            let _ = shutdown_rx.recv().await;
            return;
        }

        info!(
            contract = %self.contract_address,
            refresh_interval_secs = BOOTSTRAP_SC_REFRESH_INTERVAL.as_secs(),
            staleness_threshold_days = PEER_STALENESS_THRESHOLD.as_secs() / 86400,
            "sc_discovery started (spec 13 §4.3 tier 3)"
        );

        // Initial fan-out check: count entries in the peer book. If
        // below threshold, do an immediate fan-out — this is the
        // cold-start case (fresh node, no persisted peers from prior
        // session) and the whole point of the SC-fallback layer.
        // Read with limit = threshold + 1 so the comparison below
        // (`< threshold`) is unambiguous regardless of whether the
        // actual book has many more entries (Code Audit W2).
        let book_count = self
            .storage
            .prefix_iter_cf(
                crate::storage::schema::cf::PEER_DIRECTORY,
                PEER_ADDR_PREFIX,
                BOOTSTRAP_SC_FALLBACK_BOOK_THRESHOLD + 1,
            )
            .map(|e| e.len())
            .unwrap_or(0);
        if book_count < BOOTSTRAP_SC_FALLBACK_BOOK_THRESHOLD {
            info!(
                book_count,
                threshold = BOOTSTRAP_SC_FALLBACK_BOOK_THRESHOLD,
                "sc_discovery: cold-start detected, running immediate SC fan-out"
            );
            self.fan_out_once().await;
        } else {
            debug!(
                book_count,
                "sc_discovery: peer book sufficient, deferring to periodic refresh"
            );
        }

        // Steady-state loop. Interval cadence — periodic refresh keeps
        // the persisted book aligned with operator churn (new
        // registrations, paused nodes).
        let mut interval = tokio::time::interval(BOOTSTRAP_SC_REFRESH_INTERVAL);
        // Skip the first immediate tick — we either just ran fan_out_once
        // above OR deliberately skipped it; either way, don't double-fire.
        interval.tick().await;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.fan_out_once().await;
                }
                _ = shutdown_rx.recv() => {
                    debug!("sc_discovery shutting down");
                    break;
                }
            }
        }
    }

    /// Execute a single fan-out: query the SC for active nodes, fetch
    /// metadata, filter, persist new multiaddrs, signal reconnect.
    ///
    /// Errors from any SC call are logged at debug level and skipped
    /// — sc_discovery is best-effort and shouldn't take the node down
    /// if Klever RPC is briefly unreachable.
    async fn fan_out_once(&mut self) {
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => {
                debug!("sc_discovery: system clock before epoch, skipping");
                return;
            }
        };
        let staleness_cutoff = now.saturating_sub(PEER_STALENESS_THRESHOLD.as_secs());

        // Paginate getActiveNodes. Cap total across all pages at
        // MAX_SC_DISCOVERY_TOTAL to stay within the peer book's own
        // 256-entry cap.
        let mut offset: u32 = 0;
        let mut collected: Vec<sc_views::ActiveNode> = Vec::new();
        loop {
            match sc_views::get_active_nodes(
                &self.http,
                &self.klever_node_url,
                &self.contract_address,
                offset,
                PAGE_SIZE,
            )
            .await
            {
                Ok(page) => {
                    let page_len = page.len();
                    if page_len == 0 {
                        break;
                    }
                    collected.extend(page);
                    if collected.len() >= MAX_SC_DISCOVERY_TOTAL {
                        collected.truncate(MAX_SC_DISCOVERY_TOTAL);
                        break;
                    }
                    if (page_len as u32) < PAGE_SIZE {
                        // Short page = last page.
                        break;
                    }
                    offset = offset.saturating_add(PAGE_SIZE);
                }
                Err(e) => {
                    debug!(
                        error = %e,
                        offset,
                        "sc_discovery: getActiveNodes failed; aborting this run"
                    );
                    return;
                }
            }
        }

        if collected.is_empty() {
            debug!("sc_discovery: SC returned 0 active nodes");
            return;
        }

        // Filter by staleness and self-exclusion. The SC's
        // `getActiveNodes` view already excludes paused nodes server-
        // side (single contract, single source of truth — they cannot
        // disagree within one fan-out), so no separate `isNodePaused`
        // recheck. Earlier drafts had a per-candidate recheck for
        // defense-in-depth, but Code Audit W1 + Security Audit N2
        // surfaced it as redundant RPC load with near-zero security
        // value and meaningful liveness cost (one slow Klever endpoint
        // could stall the loop for minutes).
        let mut candidates: Vec<sc_views::ActiveNode> = Vec::with_capacity(collected.len());
        for node in collected {
            if node.address == self.self_address {
                continue;
            }
            if node.last_anchor_at == 0 || node.last_anchor_at < staleness_cutoff {
                debug!(
                    address = %node.address,
                    last_anchor_at = node.last_anchor_at,
                    cutoff = staleness_cutoff,
                    "sc_discovery: skipping stale entry"
                );
                continue;
            }
            candidates.push(node);
        }

        if candidates.is_empty() {
            debug!("sc_discovery: 0 candidates survived filtering");
            return;
        }

        info!(
            count = candidates.len(),
            "sc_discovery: fetched candidate set, fetching metadata"
        );

        // Fetch metadata per candidate, parse multiaddrs, persist.
        let mut persisted_count = 0usize;
        let mut new_addresses: HashMap<String, Vec<Multiaddr>> = HashMap::new();
        for node in &candidates {
            let multiaddrs = match sc_views::get_node_metadata(
                &self.http,
                &self.klever_node_url,
                &self.contract_address,
                &node.address,
            )
            .await
            {
                Ok(addrs) => addrs,
                Err(e) => {
                    debug!(
                        address = %node.address,
                        error = %e,
                        "sc_discovery: getNodeMetadata failed for candidate; skipping"
                    );
                    continue;
                }
            };
            if multiaddrs.is_empty() {
                // Operator deliberately did not publish a public
                // endpoint (spec 13 §6 privacy profile) — they
                // contribute to quorum without contributing to
                // discovery. Skip silently.
                continue;
            }
            let mut parsed: Vec<Multiaddr> = Vec::with_capacity(multiaddrs.len());
            for s in multiaddrs {
                match s.parse::<Multiaddr>() {
                    Ok(m) => parsed.push(m),
                    // Debug-formatted via `?` to escape newlines /
                    // control chars in attacker-controlled SC content
                    // (Security Audit W2: log forging).
                    Err(e) => debug!(
                        address = %node.address,
                        raw = ?s,
                        error = %e,
                        "sc_discovery: unparseable multiaddr; skipping"
                    ),
                }
            }
            if !parsed.is_empty() {
                new_addresses.insert(node.address.clone(), parsed);
            }
        }

        for (addr_str, multiaddrs) in &new_addresses {
            for multiaddr in multiaddrs {
                if self.persist_multiaddr(addr_str, multiaddr) {
                    persisted_count += 1;
                }
            }
        }

        if persisted_count == 0 {
            debug!("sc_discovery: no new multiaddrs persisted");
            return;
        }

        info!(
            persisted = persisted_count,
            from_candidates = new_addresses.len(),
            "sc_discovery: persisted new multiaddrs from SC registry"
        );

        // Signal NetworkService to redial out-of-cycle. try_send is
        // fine — if a previous trigger is still pending, the redial
        // will pick up our newly-persisted entries anyway.
        let _ = self.reconnect_trigger_tx.try_send(());

        // One-shot alert per startup window. The dashboard sees this
        // confirmation that the SC-fallback tier actually engaged
        // (the operational answer to "is on-chain peer discovery
        // working?"). Subsequent steady-state refreshes don't re-fire
        // to avoid noise.
        if !self.fallback_alert_fired {
            self.fallback_alert_fired = true;
            self.fire_event_alert(
                AlertType::BootstrapScFallbackUsed,
                format!(
                    "SC peer-discovery fallback engaged: persisted {} multiaddr(s) from {} registry entries",
                    persisted_count,
                    new_addresses.len()
                ),
            );
        }
    }

    /// Write a multiaddr to `PEER_DIRECTORY` under the shared `pa:`
    /// key prefix used by `NetworkService::persist_peer_addr`. The
    /// existing `dial_persisted_peers` path then dials it. Returns
    /// true iff the entry was newly written (caller uses the count
    /// for the BootstrapScFallbackUsed alert message).
    ///
    /// Key shape mirrors NetworkService's: `pa:<peer_id_str>`. We
    /// extract `peer_id` from the multiaddr's `/p2p/<peer_id>`
    /// component; if missing, the entry is skipped (a multiaddr
    /// without a peer ID can't be dialed productively by libp2p).
    fn persist_multiaddr(&self, owner_addr: &str, multiaddr: &Multiaddr) -> bool {
        let peer_id = multiaddr.iter().find_map(|proto| {
            if let libp2p::multiaddr::Protocol::P2p(id) = proto {
                Some(id)
            } else {
                None
            }
        });
        let Some(peer_id) = peer_id else {
            debug!(
                owner = ?owner_addr,
                multiaddr = ?multiaddr.to_string(),
                "sc_discovery: multiaddr lacks /p2p/<peer_id>; skipping"
            );
            return false;
        };

        let cf = crate::storage::schema::cf::PEER_DIRECTORY;

        // Enforce the same 256-entry cap that `NetworkService::persist_peer_addr`
        // uses. Without this guard, on-chain registry churn could
        // crowd out organically-learned peers (Sybil registry attacker
        // floods setNodeMetadata refreshes — Security Audit W1).
        // Check cap BEFORE the per-key get below so a full book
        // short-circuits cheaply.
        const PEER_DIRECTORY_CAP: usize = 256;
        let existing_count = self
            .storage
            .prefix_iter_cf(cf, PEER_ADDR_PREFIX, PEER_DIRECTORY_CAP + 1)
            .map(|e| e.len())
            .unwrap_or(0);

        let mut key = Vec::with_capacity(PEER_ADDR_PREFIX.len() + 64);
        key.extend_from_slice(PEER_ADDR_PREFIX);
        key.extend_from_slice(peer_id.to_string().as_bytes());

        // Already present? Skip — `dial_persisted_peers` will pick it
        // up on the next reconnect signal. The reconnect signal we
        // send below still triggers a dial against pre-existing
        // entries, which is fine (libp2p dedups by peer_id).
        let already_present = matches!(self.storage.get_cf(cf, &key), Ok(Some(_)));
        if already_present {
            return false;
        }

        // Cap check: an UPDATE to an existing key doesn't grow the
        // set (handled by the `already_present` short-circuit above);
        // only fresh inserts need to respect the cap.
        if existing_count >= PEER_DIRECTORY_CAP {
            debug!(
                cap = PEER_DIRECTORY_CAP,
                "sc_discovery: PEER_DIRECTORY at cap, skipping new entry"
            );
            return false;
        }

        let value = multiaddr.to_string();
        if let Err(e) = self.storage.put_cf(cf, &key, value.as_bytes()) {
            warn!(
                owner = ?owner_addr,
                error = %e,
                "sc_discovery: failed to persist multiaddr"
            );
            return false;
        }
        true
    }

    /// Best-effort send to the AlertEngine's event channel.
    fn fire_event_alert(&self, alert_type: AlertType, details: String) {
        let Some(tx) = self.alert_event_tx.as_ref() else {
            return;
        };
        let event = AlertEvent {
            alert_type,
            details,
        };
        if let Err(e) = tx.try_send(event) {
            debug!(error = %e, "Alert event channel full or closed; dropping event");
        }
    }
}
