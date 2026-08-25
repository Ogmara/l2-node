//! Top-level node orchestration.
//!
//! Manages the lifecycle of all node components: storage, networking,
//! chain scanner, IPFS client, API server, and notification engine.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use secrecy::ExposeSecret;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::crypto;
use crate::storage::rocks::Storage;
use crate::storage::schema::state_keys;

/// Notification retention reaper (audit final pre-mainnet W31): max rows
/// actually DELETED per sweep. Mirrors the DM retention reaper's (W11)
/// `DM_REAP_BATCH_LIMIT`.
const NOTIFICATION_REAP_BATCH_LIMIT: usize = 2_000;
/// Notification retention reaper: max rows FETCHED/examined per sweep —
/// bounds wall-clock cost even when a sweep's batch is dominated by rows
/// that aren't expired yet. Mirrors `DM_REAP_MAX_ROWS_EXAMINED`.
const NOTIFICATION_REAP_MAX_ROWS_EXAMINED: usize = 20_000;

/// Device-enc-key tombstone reaper (audit final pre-mainnet W15): max rows
/// actually DELETED per sweep. Same magnitude as the notification reaper —
/// this CF is expected to grow far more slowly (rare, rate-limited event),
/// so the cap is a wall-clock/backlog-drain safety net, not a routinely-hit
/// limit.
const DEVICE_ENC_REAP_BATCH_LIMIT: usize = 2_000;
/// Device-enc-key tombstone reaper: max rows FETCHED/examined per sweep.
const DEVICE_ENC_REAP_MAX_ROWS_EXAMINED: usize = 20_000;

/// Pure planning step for the notification retention reaper (audit final
/// pre-mainnet W31): given a batch of `NOTIFICATIONS` rows (keyed
/// `address(variable, ≤70 bytes) ++ 0xFF ++ !timestamp_be(8) ++
/// notification_id(32)`) and a cutoff, returns the keys to delete
/// (capped at `batch_limit`) and the next cursor to resume from (`None`
/// means the batch was empty — wrap to the start of the CF). No I/O —
/// factored out purely so the cutoff/key-parsing logic is unit-testable
/// without a live `Storage` (same workaround shape as the W11 DM reaper's
/// `plan_dm_msg_shaped_reap`/`plan_dm_conversations_reap`).
///
/// The address prefix is variable-width — `target_address` comes from
/// `NotificationEngine::deliver`, a delegation-resolved klv1 wallet
/// address (`encode_notification_key`, schema.rs), not attacker-supplied
/// raw text, but its exact length still isn't fixed the way a hash is —
/// so, consistent with the W11 lesson, the address length is derived
/// from the END of the key (`key.len() - 41`, the trailing
/// `0xFF(1)+!timestamp(8)+notification_id(32)` is always fixed-width),
/// never a hardcoded start offset.
fn plan_notification_reap(
    rows: &[(Vec<u8>, Vec<u8>)],
    cutoff_ms: u64,
    batch_limit: usize,
) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
    if rows.is_empty() {
        return (Vec::new(), None);
    }
    let mut to_delete = Vec::new();
    let mut last_key: &[u8] = &rows[0].0;
    for (key, _) in rows {
        // See the W11 lesson (feedback_backend_rust_patterns): only
        // advance `last_key` for rows actually examined this iteration —
        // advancing it before the batch-limit check would let the cursor
        // skip past a row whose expiry was never evaluated.
        if to_delete.len() >= batch_limit {
            break;
        }
        last_key = key;
        if key.len() <= 41 {
            continue; // defensive — malformed key
        }
        let suffix_start = key.len() - 41;
        let neg_ts =
            u64::from_be_bytes(key[suffix_start + 1..suffix_start + 9].try_into().unwrap());
        let ts = !neg_ts; // key stores the bitwise complement of the timestamp
        if ts >= cutoff_ms {
            continue; // not expired yet
        }
        to_delete.push(key.clone());
    }
    let mut next_cursor = last_key.to_vec();
    next_cursor.push(0); // sorts immediately after `last_key` itself
    (to_delete, Some(next_cursor))
}

/// Notification retention reaper (audit final pre-mainnet W31, l2-node
/// 0.104.0+): sweeps `NOTIFICATIONS` for rows older than
/// `[notifications] retention_days`, deleting them. Before this,
/// `Storage::cleanup_old_notifications` (still present, unused — kept as
/// a possible building block for a future self-service "clear my
/// notifications" endpoint, a genuinely different per-address shape than
/// this whole-CF sweep needs) had zero callers, and nothing ever
/// enforced the "30-day TTL" the schema comment has long documented as
/// policy.
///
/// Batch-capped (mirrors the DM retention reaper, W11) with a persisted
/// cursor so a large post-upgrade backlog drains incrementally across
/// ticks instead of blocking. `retention_days == 0` means "unlimited" —
/// disables the sweep, matching the `[dm]` config's identical semantic.
/// A free function (not a `Node` method) so it can be called from a
/// spawned task holding only a cloned `Storage`, not a borrow of `Node`.
fn reap_expired_notifications(storage: &Storage, retention_days: u64) {
    if retention_days == 0 {
        return;
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let cutoff_ms = now_ms.saturating_sub(retention_days.saturating_mul(24 * 3600 * 1000));
    let cursor = storage
        .get_cf(
            crate::storage::schema::cf::NODE_STATE,
            state_keys::NOTIFICATION_REAP_CURSOR,
        )
        .ok()
        .flatten()
        .unwrap_or_default();
    let rows = match storage.iter_cf_from(
        crate::storage::schema::cf::NOTIFICATIONS,
        &cursor,
        &[],
        NOTIFICATION_REAP_MAX_ROWS_EXAMINED,
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "reap_expired_notifications: scan failed");
            return;
        }
    };
    let (to_delete, next_cursor) =
        plan_notification_reap(&rows, cutoff_ms, NOTIFICATION_REAP_BATCH_LIMIT);
    for key in &to_delete {
        let _ = storage.delete_cf(crate::storage::schema::cf::NOTIFICATIONS, key);
    }
    match next_cursor {
        Some(nc) => {
            let _ = storage.put_cf(
                crate::storage::schema::cf::NODE_STATE,
                state_keys::NOTIFICATION_REAP_CURSOR,
                &nc,
            );
        }
        None => {
            let _ = storage.delete_cf(
                crate::storage::schema::cf::NODE_STATE,
                state_keys::NOTIFICATION_REAP_CURSOR,
            );
        }
    }
}

/// Pure planning step for the device-enc-key tombstone reaper (audit final
/// pre-mainnet W15): given a batch of `DEVICE_ENC_KEYS` rows and a cutoff,
/// returns the keys to delete (capped at `batch_limit`) and the next cursor
/// to resume from. No I/O — same factoring rationale as the DM/notification
/// reapers' planner functions.
///
/// Unlike those two, `DEVICE_ENC_KEYS` keys embed NO timestamp (they're
/// `wallet ++ 0xFF ++ enc_pub_hex`) — the timestamp is value-only, in the
/// stored JSON's `"ts"` field. So this planner must decode each row's value
/// rather than parse timestamp bytes out of the key, and there's no useful
/// key ordering to exploit for a "skip whole non-expired group" shortcut
/// the way the DM reaper's Pass A has — every row in the batch is decoded
/// and checked individually.
///
/// **Critical invariant**: only a row with `"revoked": true` may EVER be
/// deleted, regardless of `"ts"`. A row with `"revoked": false` (or the
/// field absent/malformed) is an ACTIVE device encryption key — it has no
/// TTL, and deleting one would break real E2E encryption for that device.
/// Getting this backwards is the one way this reaper could cause an actual
/// security regression rather than just a missed cleanup.
fn plan_device_enc_tombstone_reap(
    rows: &[(Vec<u8>, Vec<u8>)],
    cutoff_ms: u64,
    batch_limit: usize,
) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
    if rows.is_empty() {
        return (Vec::new(), None);
    }
    let mut to_delete = Vec::new();
    let mut last_key: &[u8] = &rows[0].0;
    for (key, value) in rows {
        // See the W11/W31 lesson (feedback_backend_rust_patterns): only
        // advance `last_key` for rows actually examined this iteration.
        if to_delete.len() >= batch_limit {
            break;
        }
        last_key = key;
        let Ok(record) = serde_json::from_slice::<serde_json::Value>(value) else {
            continue; // malformed value — not this reaper's job to fix
        };
        let revoked = record.get("revoked").and_then(|v| v.as_bool()).unwrap_or(false);
        if !revoked {
            continue; // ACTIVE key — never delete, regardless of age
        }
        let ts = record.get("ts").and_then(|v| v.as_u64());
        match ts {
            Some(ts) if ts < cutoff_ms => to_delete.push(key.clone()),
            _ => {} // no ts, or not expired yet — leave it
        }
    }
    let mut next_cursor = last_key.to_vec();
    next_cursor.push(0); // sorts immediately after `last_key` itself
    (to_delete, Some(next_cursor))
}

/// Device-enc-key tombstone reaper (audit final pre-mainnet W15, l2-node
/// 0.105.0+): sweeps `DEVICE_ENC_KEYS` for tombstoned (`"revoked": true`)
/// rows older than `[device_enc] tombstone_retention_days`, deleting them.
/// Before this, every accepted `DeviceEncBinding`/`DeviceEncRevoke` wrote a
/// permanent row — active or immediately superseded/revoked — and nothing
/// ever pruned an old tombstone. Combined with the `DeviceEnc` rate
/// category (`messages/router.rs`), this closes the finding from both the
/// ingest side (rate limit) and the storage side (this reaper).
///
/// Batch-capped with a persisted cursor, same shape as the DM/notification
/// reapers. `tombstone_retention_days == 0` means "unlimited" — disables
/// the sweep.
fn reap_device_enc_tombstones(storage: &Storage, tombstone_retention_days: u64) {
    if tombstone_retention_days == 0 {
        return;
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let cutoff_ms =
        now_ms.saturating_sub(tombstone_retention_days.saturating_mul(24 * 3600 * 1000));
    let cursor = storage
        .get_cf(
            crate::storage::schema::cf::NODE_STATE,
            state_keys::DEVICE_ENC_TOMBSTONE_REAP_CURSOR,
        )
        .ok()
        .flatten()
        .unwrap_or_default();
    let rows = match storage.iter_cf_from(
        crate::storage::schema::cf::DEVICE_ENC_KEYS,
        &cursor,
        &[],
        DEVICE_ENC_REAP_MAX_ROWS_EXAMINED,
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "reap_device_enc_tombstones: scan failed");
            return;
        }
    };
    let (to_delete, next_cursor) =
        plan_device_enc_tombstone_reap(&rows, cutoff_ms, DEVICE_ENC_REAP_BATCH_LIMIT);
    for key in &to_delete {
        let _ = storage.delete_cf(crate::storage::schema::cf::DEVICE_ENC_KEYS, key);
    }
    match next_cursor {
        Some(nc) => {
            let _ = storage.put_cf(
                crate::storage::schema::cf::NODE_STATE,
                state_keys::DEVICE_ENC_TOMBSTONE_REAP_CURSOR,
                &nc,
            );
        }
        None => {
            let _ = storage.delete_cf(
                crate::storage::schema::cf::NODE_STATE,
                state_keys::DEVICE_ENC_TOMBSTONE_REAP_CURSOR,
            );
        }
    }
}

/// Pending-channel-delete-claim reaper (audit final pre-mainnet W14): max
/// rows actually DELETED per sweep. Same magnitude as the device-enc
/// reaper — `ChannelDelete` is verified-identity-gated and rate-limited
/// (30/hour, `ChannelAdmin`), so this CF grows slowly; the cap is a
/// wall-clock/backlog-drain safety net, not a routinely-hit limit.
const CHANNEL_DELETE_CLAIM_REAP_BATCH_LIMIT: usize = 2_000;
/// Pending-channel-delete-claim reaper: max rows FETCHED/examined per sweep.
const CHANNEL_DELETE_CLAIM_REAP_MAX_ROWS_EXAMINED: usize = 20_000;

/// Pure planning step for the pending-channel-delete-claim reaper (audit
/// final pre-mainnet W14): given a batch of `PENDING_CHANNEL_DELETES` rows
/// (keyed `channel_id_be8`, valued `{"claimant","requested_at"}` JSON) and a
/// cutoff, returns the keys to delete (capped at `batch_limit`) and the next
/// cursor to resume from. No I/O — same factoring rationale as the other
/// reapers this session. Unlike the device-enc reaper, there's no
/// never-delete invariant to protect here: an expired, still-unclaimed
/// pending row is just a claim that never got consumed by a matching
/// `ChannelCreate` — dropping it only means a legitimately-late create (past
/// `[channel_delete] pending_retention_hours`) resurrects the channel
/// instead of converging to deleted, at which point the creator can simply
/// re-issue the delete (the channel exists locally by then, so it applies
/// immediately via the normal, non-deferred path).
fn plan_channel_delete_claim_reap(
    rows: &[(Vec<u8>, Vec<u8>)],
    cutoff_ms: u64,
    batch_limit: usize,
) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
    if rows.is_empty() {
        return (Vec::new(), None);
    }
    let mut to_delete = Vec::new();
    let mut last_key: &[u8] = &rows[0].0;
    for (key, value) in rows {
        // See the W11/W31/W15 lesson (feedback_backend_rust_patterns): only
        // advance `last_key` for rows actually examined this iteration.
        if to_delete.len() >= batch_limit {
            break;
        }
        last_key = key;
        let Ok(record) = serde_json::from_slice::<serde_json::Value>(value) else {
            continue; // malformed value — not this reaper's job to fix
        };
        let requested_at = record.get("requested_at").and_then(|v| v.as_u64());
        match requested_at {
            Some(ts) if ts < cutoff_ms => to_delete.push(key.clone()),
            _ => {} // no timestamp, or not expired yet — leave it
        }
    }
    let mut next_cursor = last_key.to_vec();
    next_cursor.push(0); // sorts immediately after `last_key` itself
    (to_delete, Some(next_cursor))
}

/// Pending-channel-delete-claim reaper (audit final pre-mainnet W14,
/// l2-node 0.106.0+): sweeps `PENDING_CHANNEL_DELETES` for claims older
/// than `[channel_delete] pending_retention_hours`, deleting them. A claim
/// is recorded when a signed `ChannelDelete` arrives for a `channel_id`
/// this node doesn't know about yet (out-of-order gossip / chain-scan lag)
/// — normally consumed the moment the channel is actually created (see
/// `messages::router::channel_delete_claim_matches` and its two call
/// sites); this reaper only cleans up claims that were never consumed
/// because no matching create ever arrived (a fake/never-used channel_id,
/// or one that genuinely never got created).
///
/// Batch-capped with a persisted cursor, same shape as the other reapers
/// this session. `pending_retention_hours == 0` means "unlimited" —
/// disables the sweep.
fn reap_channel_delete_claims(storage: &Storage, pending_retention_hours: u64) {
    if pending_retention_hours == 0 {
        return;
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let cutoff_ms = now_ms.saturating_sub(pending_retention_hours.saturating_mul(3_600_000));
    let cursor = storage
        .get_cf(
            crate::storage::schema::cf::NODE_STATE,
            state_keys::CHANNEL_DELETE_CLAIM_REAP_CURSOR,
        )
        .ok()
        .flatten()
        .unwrap_or_default();
    let rows = match storage.iter_cf_from(
        crate::storage::schema::cf::PENDING_CHANNEL_DELETES,
        &cursor,
        &[],
        CHANNEL_DELETE_CLAIM_REAP_MAX_ROWS_EXAMINED,
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "reap_channel_delete_claims: scan failed");
            return;
        }
    };
    let (to_delete, next_cursor) =
        plan_channel_delete_claim_reap(&rows, cutoff_ms, CHANNEL_DELETE_CLAIM_REAP_BATCH_LIMIT);
    for key in &to_delete {
        let _ = storage.delete_cf(crate::storage::schema::cf::PENDING_CHANNEL_DELETES, key);
    }
    match next_cursor {
        Some(nc) => {
            let _ = storage.put_cf(
                crate::storage::schema::cf::NODE_STATE,
                state_keys::CHANNEL_DELETE_CLAIM_REAP_CURSOR,
                &nc,
            );
        }
        None => {
            let _ = storage.delete_cf(
                crate::storage::schema::cf::NODE_STATE,
                state_keys::CHANNEL_DELETE_CLAIM_REAP_CURSOR,
            );
        }
    }
}

/// Pending-channel-member-removal-claim reaper batch cap (W18 residual) —
/// same numbers as `CHANNEL_DELETE_CLAIM_REAP_BATCH_LIMIT`/`_MAX_ROWS_EXAMINED`,
/// same rationale (`ChannelKick`/`Ban`/`Leave` also require on-chain-verified
/// identity and sit in low-frequency rate categories, so this CF also grows
/// slowly; the cap is a backlog-drain safety net, not a routinely-hit limit).
const CHANNEL_MEMBER_REMOVAL_REAP_BATCH_LIMIT: usize = 2_000;
const CHANNEL_MEMBER_REMOVAL_REAP_MAX_ROWS_EXAMINED: usize = 20_000;

/// Pure planning step for the pending-channel-member-removal-claim reaper
/// (W18 residual, found + fixed 2026-08-19). Structurally identical to
/// `plan_channel_delete_claim_reap` but the value is a raw 8-byte BE
/// `requested_at` (no JSON — see `PENDING_CHANNEL_MEMBER_REMOVALS`'s schema
/// doc comment), not a JSON record. Same "no never-delete invariant" shape:
/// an expired, still-unclaimed pending row just means a legitimately-late
/// `ChannelCreate` won't have this removal replayed against it — acceptable
/// same as the sibling reaper's own reasoning.
fn plan_channel_member_removal_reap(
    rows: &[(Vec<u8>, Vec<u8>)],
    cutoff_ms: u64,
    batch_limit: usize,
) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
    if rows.is_empty() {
        return (Vec::new(), None);
    }
    let mut to_delete = Vec::new();
    let mut last_key: &[u8] = &rows[0].0;
    for (key, value) in rows {
        // Only advance `last_key` for rows actually examined this iteration
        // (feedback_backend_rust_patterns cursor-correctness lesson).
        if to_delete.len() >= batch_limit {
            break;
        }
        last_key = key;
        let Ok(ts_bytes) = <[u8; 8]>::try_from(value.as_slice()) else {
            continue; // malformed value — not this reaper's job to fix
        };
        let requested_at = u64::from_be_bytes(ts_bytes);
        if requested_at < cutoff_ms {
            to_delete.push(key.clone());
        }
    }
    let mut next_cursor = last_key.to_vec();
    next_cursor.push(0); // sorts immediately after `last_key` itself
    (to_delete, Some(next_cursor))
}

/// Pending-channel-member-removal-claim reaper (W18 residual, l2-node
/// 0.108.0+): sweeps `PENDING_CHANNEL_MEMBER_REMOVALS` for claims older than
/// `[channel_member_removal] pending_retention_hours`, deleting them. A claim
/// is recorded when a `ChannelKick`/`Ban`/`Leave` arrives for a `channel_id`
/// this node doesn't know about yet — normally consumed the moment the
/// channel is actually created (see
/// `Storage::take_pending_channel_member_removals` and its two call sites);
/// this reaper only cleans up claims that were never consumed because no
/// matching create ever arrived.
fn reap_channel_member_removal_claims(storage: &Storage, pending_retention_hours: u64) {
    if pending_retention_hours == 0 {
        return;
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let cutoff_ms = now_ms.saturating_sub(pending_retention_hours.saturating_mul(3_600_000));
    let cursor = storage
        .get_cf(
            crate::storage::schema::cf::NODE_STATE,
            state_keys::CHANNEL_MEMBER_REMOVAL_REAP_CURSOR,
        )
        .ok()
        .flatten()
        .unwrap_or_default();
    let rows = match storage.iter_cf_from(
        crate::storage::schema::cf::PENDING_CHANNEL_MEMBER_REMOVALS,
        &cursor,
        &[],
        CHANNEL_MEMBER_REMOVAL_REAP_MAX_ROWS_EXAMINED,
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "reap_channel_member_removal_claims: scan failed");
            return;
        }
    };
    let (to_delete, next_cursor) = plan_channel_member_removal_reap(
        &rows,
        cutoff_ms,
        CHANNEL_MEMBER_REMOVAL_REAP_BATCH_LIMIT,
    );
    for key in &to_delete {
        let _ = storage.delete_cf(crate::storage::schema::cf::PENDING_CHANNEL_MEMBER_REMOVALS, key);
    }
    match next_cursor {
        Some(nc) => {
            let _ = storage.put_cf(
                crate::storage::schema::cf::NODE_STATE,
                state_keys::CHANNEL_MEMBER_REMOVAL_REAP_CURSOR,
                &nc,
            );
        }
        None => {
            let _ = storage.delete_cf(
                crate::storage::schema::cf::NODE_STATE,
                state_keys::CHANNEL_MEMBER_REMOVAL_REAP_CURSOR,
            );
        }
    }
}

/// Spawns `fut`, plus a lightweight second task that awaits its completion
/// purely to surface a genuine panic through structured logging (audit
/// final pre-mainnet W17). tokio's default panic hook only prints to raw
/// stderr, invisible to anything consuming `tracing` output — so a panic in
/// a non-critical background subsystem (alert engine, sc_discovery, etc.)
/// previously left no trace in logs at all. This is visibility-only, NOT
/// fail-fast: unlike the three CRITICAL tasks (network/chain/api, handled
/// directly in `Node::run`'s shutdown select), a panic here is logged but
/// does not bring down the node — losing one of these degrades a specific
/// feature, it doesn't make the node non-functional.
///
/// Returns an `AbortHandle` (not the full `JoinHandle`, which the watcher
/// task owns) so callers that need to abort this task at shutdown still
/// can — `AbortHandle::abort()` works independently of who, if anyone, is
/// awaiting the underlying `JoinHandle`.
fn spawn_supervised<F>(name: &'static str, fut: F) -> tokio::task::AbortHandle
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    supervise_handle(name, tokio::spawn(fut))
}

/// Like `spawn_supervised`, but for a task that was already spawned
/// elsewhere and has returned its `JoinHandle` (e.g.
/// `MediaLimiter::spawn_sweep_task`, which calls `tokio::spawn` internally)
/// rather than being spawned directly by the caller.
fn supervise_handle(
    name: &'static str,
    handle: tokio::task::JoinHandle<()>,
) -> tokio::task::AbortHandle {
    let abort_handle = handle.abort_handle();
    tokio::spawn(async move {
        if let Err(e) = handle.await {
            // Don't misreport an INTENTIONAL abort (shutdown cleanup calls
            // .abort() on every task) as a panic — JoinError::is_cancelled()
            // distinguishes the two cleanly.
            if !e.is_cancelled() {
                tracing::error!(task = name, error = %e, "background task panicked");
            }
        }
    });
    abort_handle
}

/// The running L2 node instance.
pub struct Node {
    /// Node configuration.
    pub config: Config,
    /// Persistent storage (RocksDB).
    pub storage: Storage,
    /// Node's Ed25519 signing key (for node-to-node communication).
    pub signing_key: SigningKey,
    /// Node ID: Base58(SHA-256(public_key)[:20]).
    pub node_id: String,
    /// Local Lamport clock counter (atomic for concurrent access).
    pub lamport_counter: Arc<AtomicU64>,
    /// Shutdown signal sender.
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl Node {
    /// Initialize a new node from configuration.
    ///
    /// Opens storage, loads or generates the node identity key,
    /// and prepares all components for startup.
    pub async fn init(config: Config) -> Result<Self> {
        // Ensure data directory exists with restrictive permissions
        let data_dir = &config.node.data_dir;
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("creating data directory: {}", data_dir.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(data_dir, perms)
                .with_context(|| "setting data directory permissions")?;
        }

        // Open storage
        let db_path = data_dir.join("db");
        let storage =
            Storage::open(&db_path).with_context(|| "opening RocksDB storage")?;

        // Phase 2 snapshot bootstrap crash recovery — detect a half-applied
        // snapshot and restore from the rollback checkpoint before we touch
        // the DB further. The window is: rollback dir persisted, destructive
        // apply ops began, but the SNAPSHOT_APPLIED_AT_HEIGHT sentinel was
        // never written. See spec 11-snapshot-sync.md §5a.6.
        let storage = check_snapshot_apply_recovery(storage, &db_path)?;

        // Load or generate node identity key
        let signing_key = load_or_generate_key(&storage)?;
        let node_id = crypto::compute_node_id(&signing_key.verifying_key());

        // Rebuild stat counters if they're zero but data exists
        // (handles first upgrade from pre-stats versions)
        let has_v2_counters = storage.get_stat(state_keys::COUNTERS_V2)? > 0;
        if !has_v2_counters {
            if let Err(e) = storage.rebuild_stat_counters() {
                warn!(error = %e, "Failed to rebuild stat counters");
            }
        }

        // Normalize channel_type values from string to u8 (one-time migration)
        let ct_normalized = storage.get_stat(state_keys::CHANNEL_TYPE_NORMALIZED)? > 0;
        if !ct_normalized {
            if let Err(e) = storage.normalize_channel_types() {
                warn!(error = %e, "Failed to normalize channel_type values");
            }
        }

        // Backfill DEVICE_WALLET_MAP from DELEGATIONS (one-time migration)
        let dm_backfilled = storage.get_stat(state_keys::DELEGATION_MAP_BACKFILLED)? > 0;
        if !dm_backfilled {
            if let Err(e) = storage.backfill_delegation_map() {
                warn!(error = %e, "Failed to backfill delegation map");
            }
        }

        // Migrate device addresses from klv1... to ogd1... prefix (one-time migration)
        let hrp_migrated = storage.get_stat(state_keys::DEVICE_HRP_MIGRATED)? > 0;
        if !hrp_migrated {
            if let Err(e) = storage.migrate_device_hrp() {
                warn!(error = %e, "Failed to migrate device address HRP");
            }
        }

        // Rebuild reaction-count CFs with the v2 length-prefixed key format
        // (audit 2026-06-07 C3). Recounts from the per-reaction CFs (source of
        // truth), so old unframed count keys are cleared. One-time migration.
        let reaction_counts_v2 = storage.get_stat(state_keys::REACTION_COUNT_KEYV2)? > 0;
        if !reaction_counts_v2 {
            if let Err(e) = storage.migrate_reaction_count_keys() {
                warn!(error = %e, "Failed to rebuild reaction-count keys (v2)");
            }
        }

        // Backfill USERS_BY_NAME prefix index from USERS (one-time migration).
        // Required so the v0.32.0 mention-autocomplete endpoint returns
        // pre-existing users immediately, not just users who update their
        // profile after the upgrade.
        let users_by_name_backfilled = storage.get_stat(state_keys::USERS_BY_NAME_BACKFILLED)? > 0;
        if !users_by_name_backfilled {
            if let Err(e) = storage.backfill_users_by_name() {
                warn!(error = %e, "Failed to backfill USERS_BY_NAME index");
            }
        }

        // Backfill IDENTITY_ENVELOPES from MESSAGES (one-time, P-1 identity-sync).
        // Runs after the delegation-map backfill above so device-authored
        // profile/follow envelopes resolve to their wallet. Lets a node upgraded
        // with history serve pre-existing delegations/profiles/follows.
        let identity_envelopes_indexed =
            storage.get_stat(state_keys::IDENTITY_ENVELOPES_INDEXED)? > 0;
        if !identity_envelopes_indexed {
            if let Err(e) = storage.backfill_identity_envelopes() {
                warn!(error = %e, "Failed to backfill IDENTITY_ENVELOPES index");
            }
        }

        // Backfill CHANNEL_META_MSGS from MESSAGES (one-time, P-3b channel
        // metadata) so the channel-history reconcile can serve channel
        // name/logo/membership to nodes that chain-discovered the channel.
        let channel_meta_indexed = storage.get_stat(state_keys::CHANNEL_META_INDEXED)? > 0;
        if !channel_meta_indexed {
            if let Err(e) = storage.backfill_channel_meta() {
                warn!(error = %e, "Failed to backfill CHANNEL_META_MSGS index");
            }
        }

        // Backfill CHANNEL_EDIT_DELETE_MSGS/DM_EDIT_DELETE_MSGS/NEWS_EDIT_DELETE
        // from MESSAGES (one-time, audit final pre-mainnet W6) so edits/deletes
        // that predate this migration also propagate via reconcile/dm-sync/
        // news-sync backfill instead of being permanently unerasable on any
        // fresh/cold-joining node.
        let edit_delete_markers_indexed =
            storage.get_stat(state_keys::EDIT_DELETE_MARKERS_INDEXED)? > 0;
        if !edit_delete_markers_indexed {
            if let Err(e) = storage.backfill_edit_delete_markers() {
                warn!(error = %e, "Failed to backfill edit/delete marker indexes");
            }
        }

        // Re-key CHANNEL_MSGS from lamport_ts (always 0) to wall-clock timestamp
        // so the channel index is chronological + the unread fast-skip works.
        let channel_msgs_ts_reindexed =
            storage.get_stat(state_keys::CHANNEL_MSGS_TS_REINDEXED)? > 0;
        if !channel_msgs_ts_reindexed {
            if let Err(e) = storage.reindex_channel_msgs_by_timestamp() {
                warn!(error = %e, "Failed to re-index CHANNEL_MSGS by timestamp");
            }
        }

        // Load Lamport counter from storage
        let lamport_value = storage.get_lamport_counter()?;
        let lamport_counter = Arc::new(AtomicU64::new(lamport_value));

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

        let wallet_address = crate::crypto::pubkey_to_address(&signing_key.verifying_key())
            .unwrap_or_else(|_| "unknown".to_string());
        info!(
            node_id = %node_id,
            address = %wallet_address,
            data_dir = %data_dir.display(),
            "Node initialized — this wallet address is your node's identity. \
             Back up your key with: ogmara-node export-key"
        );

        Ok(Self {
            config,
            storage,
            signing_key,
            node_id,
            lamport_counter,
            shutdown_tx,
        })
    }

    /// Get the node's public key.
    pub fn public_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the node's Klever address.
    pub fn address(&self) -> Result<String> {
        crypto::pubkey_to_address(&self.public_key())
            .map_err(|e| anyhow::anyhow!("computing node address: {}", e))
    }

    /// Get a receiver for the shutdown signal.
    pub fn shutdown_rx(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Signal all components to shut down.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Convert the node's Ed25519 signing key to a libp2p identity keypair.
    pub fn libp2p_keypair(&self) -> Result<libp2p::identity::Keypair> {
        // audit 2026-06-07 (W23): the intermediate buffers hold raw secret-key
        // material. Bind them so we can scrub them after the keypair is built
        // (mirrors the anchorer-key zeroize pattern with `.fill(0)` below in
        // this file). `try_from_bytes` takes `&mut` but does not guarantee it
        // zeroes the slice, and our `secret_bytes` copy is separate, so we
        // clear both explicitly even on the error path.
        let mut secret_bytes = self.signing_key.to_bytes();
        let mut keypair_bytes =
            [secret_bytes, *self.signing_key.verifying_key().as_bytes()].concat();
        let result = libp2p::identity::ed25519::Keypair::try_from_bytes(&mut keypair_bytes)
            .context("converting Ed25519 key to libp2p keypair");
        // Scrub the secret material regardless of success/failure.
        secret_bytes.fill(0);
        keypair_bytes.fill(0);
        Ok(libp2p::identity::Keypair::from(result?))
    }

    /// Run the node until shutdown is signaled.
    ///
    /// Starts the network layer, message router, and all background tasks.
    pub async fn run(&self) -> Result<()> {
        info!(node_id = %self.node_id, "Starting Ogmara L2 node");

        // audit 2026-06-07 (W22): the snapshot anchor re-verification is a
        // security control. If an operator left the experimental bypass on,
        // make it impossible to miss in the boot logs — not just buried in
        // the snapshot-bootstrap path that only fires on a fresh node.
        if self.config.snapshot.experimental_skip_anchor_verify {
            warn!(
                "SECURITY: snapshot.experimental_skip_anchor_verify = true — \
                 Klever anchor re-verification of snapshots is DISABLED. \
                 A dishonest snapshot producer cannot be detected. \
                 Use only on fully-controlled networks; set to false for production."
            );
        }

        // Initialize identity resolver (device → wallet mapping cache)
        let identity = crate::storage::identity::IdentityResolver::new(self.storage.clone());
        match identity.warm_cache() {
            Ok(count) if count > 0 => info!(count, "Identity cache warmed"),
            Ok(_) => {}
            Err(e) => warn!(error = %e, "Failed to warm identity cache"),
        }

        // Create shared broadcast channel (used by WS layer, notification engine, etc.)
        let (ws_broadcast, _) =
            tokio::sync::broadcast::channel::<Arc<crate::api::state::WsOutbound>>(1024);

        // Initialize notification engine before the network service so gossip
        // messages can be fed to it immediately.
        let notification_engine = if self.config.push_gateway.enabled
            && !self.config.push_gateway.url.is_empty()
        {
            let mut engine = crate::notifications::engine::NotificationEngine::new(
                ws_broadcast.clone(),
                Some(self.config.push_gateway.url.clone()),
                if self.config.push_gateway.auth_token.is_empty() {
                    None
                } else {
                    Some(self.config.push_gateway.auth_token.clone())
                },
                self.config.notifications.max_stored_per_address,
            );
            engine.set_storage(self.storage.clone());
            info!(
                url = %self.config.push_gateway.url,
                "Notification engine initialized with push gateway"
            );
            Some(Arc::new(engine))
        } else {
            // Even without push gateway, create the engine for WS-only notifications
            let mut engine = crate::notifications::engine::NotificationEngine::new(
                ws_broadcast.clone(),
                None,
                None,
                self.config.notifications.max_stored_per_address,
            );
            engine.set_storage(self.storage.clone());
            info!("Notification engine initialized (WS-only, no push gateway)");
            Some(Arc::new(engine))
        };

        // Shared peer counter (updated by network layer, read by API health endpoint)
        let peer_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

        // Shared network counters for metrics (spec 10-dashboard.md §6.2)
        let network_counters = Arc::new(crate::metrics::counters::NetworkCounters::new());

        // Shared connected-peers map (updated by network layer on Identify, read by API /network/nodes)
        let connected_peers = Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));

        // Shared snapshot cache — populated by the background cache builder
        // (spec 11-snapshot-sync.md §1). `None` until the first build completes.
        let snapshot_cache: crate::network::snapshot::SharedSnapshotCache =
            Arc::new(std::sync::RwLock::new(None));

        // Channel for snapshot-client commands (Phase 2). The bootstrap
        // orchestrator (if enabled) uses this channel to dispatch outbound
        // snapshot requests via NetworkService.
        let (snapshot_client_tx, snapshot_client_rx) =
            tokio::sync::mpsc::unbounded_channel::<crate::network::SnapshotClientCommand>();

        // Spec 13 §4.3 stall-trigger signal — bumped by NetworkService
        // on every successful Ogmara Identify, read once by sc_discovery
        // at +60s post-startup. Cloned BEFORE NetworkService::new so the
        // sc_discovery handle below shares the same counter.
        let identify_success_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        // Spec 13 §4.1 discovery-source classifier — sc_discovery
        // pushes PeerIds it persists, NetworkService reads at
        // Identify::Received time to tag the connected peer with `sc`
        // tier. Owned outside both tasks; both get cloned Arcs.
        let sc_added_peer_ids = std::sync::Arc::new(std::sync::RwLock::new(
            std::collections::HashSet::<libp2p::PeerId>::new(),
        ));

        // Spec 10 §9.2 (l2-node 0.46.6+) — B4 instrumentation. Both
        // shared between `NetworkService` (writer) and `AppState`
        // (reader for the `/admin/network/mesh-stats` endpoint).
        let mesh_stats_handle = crate::network::mesh_stats::shared_empty();
        let publish_failure_counters =
            crate::network::mesh_stats::PublishFailureCounters::default();

        // Pre-allocate the alert event channel so `NetworkService`
        // (the `publish_failed_insufficient_peers` alert firer) and
        // the rest of the task graph share the same handle. Receiver
        // is consumed by `AlertEngine` later in this method. Channel
        // allocation is cheap; the senders are cloned per-task and
        // gated on `[alerts] enabled`.
        let (alert_event_tx, alert_event_rx) =
            crate::notifications::alerts::AlertEngine::event_channel();

        // Start the network service
        let keypair = self.libp2p_keypair()?;
        let mut network = crate::network::NetworkService::new(
            &self.config,
            self.storage.clone(),
            identity.clone(),
            keypair,
            notification_engine.clone(),
            peer_count.clone(),
            self.signing_key.clone(),
            self.node_id.clone(),
            connected_peers.clone(),
            network_counters.clone(),
            snapshot_cache.clone(),
            snapshot_client_rx,
            identify_success_count.clone(),
            sc_added_peer_ids.clone(),
            publish_failure_counters.clone(),
            mesh_stats_handle.clone(),
            // Alert sender — gated on `[alerts] enabled` so the network
            // task does not hold a live channel half against a missing
            // engine. The same gate is used elsewhere in this method
            // (sc_discovery, metadata reconciler).
            if self.config.alerts.enabled {
                Some(alert_event_tx.clone())
            } else {
                None
            },
            // Spec 1 §channel-history-reconciliation (l2-node 0.47.0+) —
            // cloned snapshot used both for the cold-join trigger
            // (subscribe_channel) and the responder-side rate limits.
            self.config.backfill.clone(),
            // Spec 3 §dm-offline-store-and-forward (l2-node 0.69.0+) —
            // persistent DM-subscription cap/LRU + dm-sync backfill window.
            self.config.dm.clone(),
        )
        .await
        .context("starting network service")?;

        let network_peer_id = network.local_peer_id().to_string();
        // Capture a shared handle to the presence manager before
        // `network` is moved into the spawn (spec 13 §10, l2-node
        // 0.48.0+). `None` when `[network.presence] enabled = false`.
        // The handle is cloned into AppState so the REST handlers can
        // serve the cache; the manager's background sweep runs as a
        // separate task below.
        let presence_manager_handle = network.presence_manager();
        info!(
            peer_id = %network_peer_id,
            "Network service started"
        );

        // Spawn the presence-cache TTL sweep task (spec 13 §10.4).
        // Only when the operator opted in.
        if let Some(ref mgr) = presence_manager_handle {
            let sweep_mgr = mgr.clone();
            let sweep_shutdown_rx = self.shutdown_rx();
            spawn_supervised("presence_sweep", async move {
                sweep_mgr.run_sweep(sweep_shutdown_rx).await;
            });
        }

        // Channel for chain scanner → network layer topic subscriptions. Cloned for
        // AppState so the `/channels/{id}/federate` endpoint can subscribe to a
        // private channel's topic on demand (F1 federation) via the same path.
        let (channel_tx, channel_rx) = tokio::sync::mpsc::unbounded_channel::<u64>();
        let channel_subscribe_tx = channel_tx.clone();

        // Channel for API layer → network layer GossipSub publishing
        let (gossip_tx, gossip_rx) =
            tokio::sync::mpsc::unbounded_channel::<crate::network::GossipPublish>();

        // Channel for API/router → network: lazy per-wallet identity-sync pulls
        // (P-1, l2-node 0.50.0+).
        let (identity_sync_tx, identity_sync_rx) =
            tokio::sync::mpsc::unbounded_channel::<crate::network::IdentitySyncCommand>();

        // Channel for API/WS → network: subscribe a wallet's DM gossip topic on WS
        // connect so this node receives that user's cross-node DMs (0.60.0),
        // optionally carrying a wallet-signed dm-sync backfill authorization
        // for this node (audit W5).
        let (dm_subscribe_tx, dm_subscribe_rx) =
            tokio::sync::mpsc::unbounded_channel::<crate::network::DmSubscribeEvent>();

        // Subscribe to all existing channels from storage so the node
        // participates in GossipSub for channels it already knows about.
        match self.storage.prefix_iter_cf(
            crate::storage::schema::cf::CHANNELS,
            &[],
            100_000,
        ) {
            Ok(entries) => {
                let mut count = 0u64;
                for (key, _) in &entries {
                    if key.len() == 8 {
                        let channel_id = u64::from_be_bytes(
                            <[u8; 8]>::try_from(key.as_slice()).expect("len checked"),
                        );
                        network.subscribe_channel(channel_id);
                        count += 1;
                    }
                }
                if count > 0 {
                    info!(count, "Subscribed to existing channel topics");
                }
            }
            Err(e) => warn!(error = %e, "Failed to load existing channels for GossipSub"),
        }

        // Subscribe to pinned channels (may overlap with above, subscribe_channel is idempotent)
        for &channel_id in &self.config.storage.pinned_channels {
            network.subscribe_channel(channel_id);
        }

        // Persist Lamport counter periodically
        let storage = self.storage.clone();
        let lamport = self.lamport_counter.clone();
        let mut lamport_shutdown_rx = self.shutdown_rx();

        let lamport_task = spawn_supervised("lamport_persist", async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let val = lamport.load(Ordering::SeqCst);
                        if let Err(e) = storage.set_lamport_counter(val) {
                            warn!(error = %e, "Failed to persist Lamport counter");
                        }
                    }
                    _ = lamport_shutdown_rx.recv() => break,
                }
            }
        });

        // v0.44.0: cross-task channel between sc_discovery (sender,
        // spawned later once alert_event_tx and node_address are in
        // scope) and NetworkService::run (receiver, attached here).
        // The receiver is consumed by `network.run` to trigger out-of-
        // cycle `dial_persisted_peers` calls when sc_discovery
        // persists fresh entries. Capacity 4 is plenty — bursts
        // coalesce because all we care about is "redial recently".
        let (sc_reconnect_tx, sc_reconnect_rx) = tokio::sync::mpsc::channel::<()>(4);

        // Run network event loop in a task
        let network_shutdown_rx = self.shutdown_rx();
        let mut network_task = tokio::spawn(async move {
            network
                .run(network_shutdown_rx, channel_rx, gossip_rx, sc_reconnect_rx, identity_sync_rx, dm_subscribe_rx)
                .await;
        });

        // Phase 2 snapshot bootstrap (opt-in). Blocks startup so the chain
        // scanner reads the post-apply cursor. Falls back to scan on any
        // failure path. Spec 11-snapshot-sync.md §5 (Phase 2).
        if self.config.snapshot.bootstrap_enabled {
            let cursor = self.storage.get_chain_cursor().unwrap_or(0);
            // "Fresh" is strict — cursor == 0. The earlier formulation
            // `cursor < start_block` was fragile: an operator who sets
            // `start_block` HIGH (e.g. 9_100_000 for testnet) on an
            // existing healthy node with cursor=9_000_000 would have seen
            // is_fresh=true and the apply would clobber their state.
            // (Audit finding Phase 2 Sec W1.)
            let is_fresh = cursor == 0;
            if !is_fresh && self.config.snapshot.bootstrap_only_if_fresh {
                info!(
                    cursor,
                    start_block = self.config.klever.start_block,
                    "Snapshot bootstrap enabled but node is NOT FRESH (chain_cursor > 0) — skipping. \
                     To force a fresh bootstrap on this node: stop it, delete the data_dir's `db/` \
                     subdirectory, restart. Alternatively set `bootstrap_only_if_fresh = false` in \
                     ogmara.toml under [snapshot] (will overwrite ALL existing local L2 state with \
                     the snapshot — only do this if you understand the implications)."
                );
            } else if !is_fresh && !self.config.snapshot.allow_apply_over_existing {
                warn!(
                    cursor,
                    "Snapshot bootstrap requested over non-fresh node but allow_apply_over_existing=false — skipping"
                );
            } else {
                let handle = crate::network::snapshot_client::ClientHandle::new(
                    snapshot_client_tx.clone(),
                    &self.config.snapshot,
                );
                let storage_arc = Arc::new(self.storage.clone());
                let snap_config = self.config.snapshot.clone();
                let network_id = self.config.network_id().to_string();
                let klever_node_url = self.config.klever.node_url.clone();
                let contract_address = self.config.klever.contract_address.clone();
                let data_dir = self.config.node.data_dir.clone();
                info!("Snapshot bootstrap starting (anchor-verified)");
                match crate::network::snapshot_client::run_bootstrap(
                    &handle,
                    storage_arc,
                    &snap_config,
                    &network_id,
                    &klever_node_url,
                    &contract_address,
                    &data_dir,
                )
                .await
                {
                    Ok(Some(outcome)) => {
                        info!(
                            applied_at = outcome.applied_at,
                            new_cursor = outcome.new_cursor,
                            rollback_dir = %outcome.rollback_dir.display(),
                            "Snapshot bootstrap succeeded — chain scanner will resume from new cursor"
                        );
                    }
                    Ok(None) => {
                        warn!("Snapshot bootstrap skipped — falling back to chain scan");
                    }
                    Err(e) => {
                        warn!(error = %e, "Snapshot bootstrap failed — falling back to chain scan");
                    }
                }
            }
        }

        // Audit final pre-mainnet W35: shared millis-since-epoch of the last
        // successful Klever RPC call, written by ChainScanner/StateAnchorer/
        // MetadataReconciler/ScDiscovery, read by MetricsCollector into
        // MetricsSnapshot::klever_rpc_last_success_ms for the
        // KleverDisconnected alert. `0` (never succeeded) is a meaningful
        // initial value — the alert fires from cold start until the first
        // success, same as the existing `ipfs_connected` check's own
        // "not yet confirmed = unreachable" default. Declared here (before
        // the chain scanner spawn below) since it's the first of the 4
        // Klever-calling tasks to start.
        let klever_health = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

        // Start chain scanner
        let chain_config = self.config.klever.clone();
        let chain_storage = self.storage.clone();
        let chain_shutdown_rx = self.shutdown_rx();
        let chain_klever_health = klever_health.clone();
        let mut chain_task = tokio::spawn(async move {
            match crate::chain::scanner::ChainScanner::new(chain_config, chain_storage, channel_tx, chain_klever_health) {
                Ok(mut scanner) => scanner.run(chain_shutdown_rx).await,
                Err(e) => warn!(error = %e, "Failed to start chain scanner"),
            }
        });

        // Snapshot cache builder — periodically rebuilds the served snapshot
        // from current storage state (spec 11-snapshot-sync.md §1).
        // Phase 1: serve-only. The cache lives in `snapshot_cache` (shared
        // with NetworkService); rebuild cadence is configurable.
        if self.config.snapshot.serve_enabled {
            let snap_storage = self.storage.clone();
            let snap_signing_key = self.signing_key.clone();
            let snap_node_id = self.node_id.clone();
            let snap_network_id = self.config.network_id().to_string();
            let snap_cache = snapshot_cache.clone();
            let snap_config = self.config.snapshot.clone();
            let mut snap_shutdown_rx = self.shutdown_rx();
            let _snapshot_task = spawn_supervised("snapshot_cache_rebuild", async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                    snap_config.serve_rebuild_interval_secs.max(60),
                ));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                // First tick fires immediately — consume it.
                tick.tick().await;

                // Deferred-start: 60s warm-up so node boot isn't blocked by a
                // full CF scan on every restart. Exit immediately on shutdown
                // — don't make Ctrl-C wait a full minute.
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                    _ = snap_shutdown_rx.recv() => {
                        info!("Snapshot cache builder shutting down (during warm-up)");
                        return;
                    }
                }

                loop {
                    let storage_for_build = snap_storage.clone();
                    let signing_for_build = snap_signing_key.clone();
                    let node_id_for_build = snap_node_id.clone();
                    let network_id_for_build = snap_network_id.clone();
                    let chunk_size = snap_config.chunk_size_bytes;

                    let build = tokio::task::spawn_blocking(move || {
                        crate::network::snapshot::build_cache(
                            &storage_for_build,
                            &network_id_for_build,
                            &node_id_for_build,
                            &signing_for_build,
                            chunk_size,
                            crate::storage::schema::snapshot::codec::ZSTD,
                        )
                    })
                    .await;

                    match build {
                        Ok(Ok(cache)) => {
                            let height = cache.manifest.block_height;
                            let root_hex = hex::encode(cache.manifest.snapshot_root);
                            let bytes = cache.compressed_total_bytes;
                            let chunks = cache.chunks.len();
                            // Swap the new cache in, then drop the old one
                            // OUTSIDE the write-lock so freeing the multi-MiB
                            // chunk vecs doesn't block readers/serve handlers.
                            let prev = match snap_cache.write() {
                                Ok(mut guard) => guard.replace(cache),
                                Err(e) => {
                                    warn!(error = %e, "snapshot cache lock poisoned");
                                    None
                                }
                            };
                            drop(prev);
                            crate::network::snapshot::record_serve_height(&snap_storage, height);
                            info!(
                                block_height = height,
                                snapshot_root = %root_hex,
                                chunks,
                                compressed_bytes = bytes,
                                "Snapshot cache rebuilt"
                            );
                        }
                        Ok(Err(e)) => {
                            warn!(error = %e, "Snapshot cache build failed");
                        }
                        Err(e) => {
                            warn!(error = %e, "Snapshot cache build task panicked");
                        }
                    }

                    tokio::select! {
                        _ = tick.tick() => {}
                        _ = snap_shutdown_rx.recv() => {
                            info!("Snapshot cache builder shutting down");
                            break;
                        }
                    }
                }
            });
        }

        // Shared anchor-divergence + canonical counters. Written by
        // `StateAnchorer::check_divergence`, read by `MetricsCollector`
        // (for the `anchor_divergence` alert) and by `AppState` (for
        // the `/admin/node/registration` admin endpoint). Spec 12 §6.1
        // — process-local counters; reset across node restarts is
        // intentional and documented.
        let anchor_divergence_counter =
            std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let anchor_canonical_counter =
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

        // Anchorer-side alert handle: cloned per-task. The channel
        // itself was pre-allocated above (before `NetworkService::new`)
        // so the network task could also receive a sender. None when
        // alerts disabled — tasks suppress event firing in that case.
        let anchor_alert_tx: Option<crate::notifications::alerts::AlertEventSender> =
            if self.config.alerts.enabled {
                Some(alert_event_tx.clone())
            } else {
                None
            };

        // Start state anchorer (if enabled).
        // `anchor_task` is awaited explicitly on shutdown so a graceful
        // pauseNode (when `pause_on_shutdown = true`) has time to
        // broadcast before the rest of the node tears down. None when
        // anchoring is disabled.
        let mut anchor_task: Option<tokio::task::JoinHandle<()>> = None;
        let (anchor_trigger_tx, governance_submit_tx, anchor_wallet_address) = if self.config.anchoring.enabled {
            let anchor_klever = self.config.klever.clone();
            let anchor_config = self.config.anchoring.clone();
            let anchor_storage = self.storage.clone();
            let anchor_node_id = self.node_id.clone();
            let anchor_divergence_for_task = anchor_divergence_counter.clone();
            let anchor_canonical_for_task = anchor_canonical_counter.clone();
            let anchor_klever_health = klever_health.clone();

            // Resolve wallet key: env var > config file > node identity key.
            // Both candidate sources are wrapped in `SecretString` so the
            // hex source zeroizes on drop when this scope exits — no
            // manual zeroize dance, no `unsafe` (v0.46.0 Phase C / plan C1
            // replaces the v0.45.0 manual zeroize hot-loop).
            let wallet_key_secret: Option<secrecy::SecretString> =
                std::env::var("OGMARA_ANCHOR_WALLET_KEY")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .map(secrecy::SecretString::from)
                    .or_else(|| anchor_config.wallet_key.clone());

            let anchor_key = match wallet_key_secret.as_ref() {
                None => {
                    info!("State anchoring using node identity key");
                    self.signing_key.clone()
                }
                Some(secret) => {
                    let hex_str = secret.expose_secret();
                    let mut bytes = hex::decode(hex_str)
                        .context("decoding anchor wallet key hex")?;
                    // Security Audit NOTE-2 fix (same gap independently
                    // flagged in `alert_channel.rs::load_alert_signing_key`):
                    // check the length BEFORE building `key_bytes`, zeroizing
                    // `bytes` on EITHER exit path. `try_into().map_err(...)?`
                    // used to return on a length mismatch before reaching the
                    // `fill(0)` below, leaving decoded secret bytes
                    // unzeroized in the `Vec` its `Drop` then just frees as-is.
                    if bytes.len() != 32 {
                        let len = bytes.len();
                        bytes.fill(0);
                        anyhow::bail!("anchor wallet key must be 32 bytes, got {len}");
                    }
                    let mut key_bytes: [u8; 32] =
                        bytes.as_slice().try_into().expect("length checked above");
                    let key = SigningKey::from_bytes(&key_bytes);
                    // Zeroize BOTH the decoded `bytes` Vec AND the
                    // intermediate `[u8; 32]` array — neither is wrapped
                    // by secrecy, both currently hold the raw private
                    // key. SigningKey itself ZeroizeOnDrop per
                    // ed25519-dalek 2.x, so `key`'s residence is bounded
                    // by its own scope. The hex source drops + zeroizes
                    // when `wallet_key_secret` falls out at the end of
                    // this block (Phase C Security Audit N2).
                    bytes.fill(0);
                    key_bytes.fill(0);
                    info!("State anchoring using separate wallet key");
                    key
                }
            };
            // Governance actions (governance-dashboard-plan.md Phase 6)
            // are signed with this SAME anchor key, so the address the
            // dashboard shows as "the wallet voting on your behalf"
            // must be computed here, before `anchor_key` moves into the
            // spawned task below — it can legitimately differ from
            // `self.address()` (the node's own identity key) when a
            // separate `[anchoring] wallet_key` is configured.
            let anchor_wallet_address_computed =
                crate::crypto::pubkey_to_address(&anchor_key.verifying_key())
                    .context("computing anchor wallet address for governance display")?;
            // Explicit drop is documentation-of-intent — `wallet_key_secret`
            // would naturally scope-exit at the next `}`, but making the
            // zeroize boundary visible at the line a reviewer looks for
            // is worth the line (Phase C Code Audit N).
            drop(wallet_key_secret);
            let anchor_shutdown_rx = self.shutdown_rx();
            let (trigger_tx, trigger_rx) = tokio::sync::mpsc::channel(1);
            // Governance-submit channel (Phase 6) — capacity 4, not 1:
            // unlike the periodic anchor trigger (naturally rate-limited
            // by "how often does a human click Trigger Anchor"), a
            // single admin operator may click create/vote/execute in
            // quick succession across a few open browser tabs.
            let (gov_tx, gov_rx) = tokio::sync::mpsc::channel::<
                crate::chain::anchoring::GovernanceSubmitRequest,
            >(4);
            let anchor_alert_for_task = anchor_alert_tx.clone();
            // Capture the JoinHandle so the main loop can `await` the
            // anchor task on shutdown — when `pause_on_shutdown = true`
            // we need its `submit_pause_for_shutdown()` call to finish
            // broadcasting before we abort the rest of the node.
            let handle = tokio::spawn(async move {
                match crate::chain::anchoring::StateAnchorer::new(
                    anchor_klever,
                    anchor_config,
                    anchor_storage,
                    anchor_key,
                    anchor_node_id,
                    anchor_divergence_for_task,
                    anchor_canonical_for_task,
                    anchor_alert_for_task,
                    anchor_klever_health,
                ) {
                    Ok(mut anchorer) => anchorer.run(anchor_shutdown_rx, trigger_rx, gov_rx).await,
                    Err(e) => warn!(error = %e, "Failed to start state anchorer"),
                }
            });
            anchor_task = Some(handle);
            (Some(trigger_tx), Some(gov_tx), Some(anchor_wallet_address_computed))
        } else {
            (None, None, None)
        };

        // IPFS client (stored for API media endpoints)
        let ipfs_client = match crate::ipfs::client::IpfsClient::new(&self.config.ipfs) {
            Ok(ipfs) => {
                match ipfs.health_check().await {
                    Ok(true) => {
                        info!("IPFS node connected");
                        Some(ipfs)
                    }
                    Ok(false) => {
                        warn!("IPFS node not reachable at {}", self.config.ipfs.api_url);
                        Some(ipfs) // keep client — node may come online later
                    }
                    Err(e) => {
                        warn!(error = %e, "IPFS health check failed");
                        Some(ipfs)
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to create IPFS client");
                None
            }
        };

        // Initialize PoW anti-spam manager
        let pow_manager = if self.config.api.pow.enabled {
            let mgr = Arc::new(crate::pow::PowManager::new(
                self.config.api.pow.clone(),
                self.storage.clone(),
            ));
            info!(
                difficulty = self.config.api.pow.difficulty,
                ttl = self.config.api.pow.challenge_ttl_seconds,
                "PoW anti-spam enabled"
            );
            Some(mgr)
        } else {
            info!("PoW anti-spam disabled");
            None
        };

        // Use the authoritative network_id from config (set during migration/validation).
        // This is the single source of truth — also used by libp2p protocol IDs and topics.
        let klever_network = self.config.network_id().to_string();

        // Start REST/WS API server
        let api_router = crate::messages::router::MessageRouter::new(
            self.storage.clone(),
            identity.clone(),
            pow_manager.clone(),
            klever_network.clone(),
            self.config.dm.max_stored_messages_per_recipient,
            network_counters.clone(),
        );

        // Start metrics collector (spec 10-dashboard.md §6)
        let node_address = self.address().unwrap_or_default();
        let metrics_collector = crate::metrics::MetricsCollector::new(
            self.config.metrics.clone(),
            self.storage.clone(),
            ipfs_client.clone(),
            peer_count.clone(),
            network_counters.clone(),
            &self.config.node.data_dir.to_string_lossy(),
            self.node_id.clone(),
            self.config.klever.api_url.clone(),
            node_address.clone(),
            anchor_divergence_counter.clone(),
            self.config.storage.max_db_size_gb,
            klever_health.clone(),
        );
        let metrics_latest = metrics_collector.latest_handle();
        let metrics_history = metrics_collector.history_handle();

        if self.config.metrics.enabled {
            let metrics_shutdown_rx = self.shutdown_rx();
            spawn_supervised("metrics_collector", async move {
                metrics_collector.run(metrics_shutdown_rx).await;
            });
            info!("Metrics collector started");
        }

        // Create shared alert history (readable by dashboard, writable by alert engine)
        let alert_history: crate::notifications::alerts::SharedAlertHistory =
            std::sync::Arc::new(std::sync::RwLock::new(std::collections::VecDeque::new()));

        // Start alert engine (if enabled, spec 10-dashboard.md §9).
        // The events_rx half of the cross-task event channel was
        // allocated upstream (see `alert_event_tx` block). When alerts
        // are disabled we drop `alert_event_rx` here; the matching
        // `anchor_alert_tx`/`sc_alert_tx` handles passed to background
        // tasks were already gated to `None`, so they no-op cleanly.
        if self.config.alerts.enabled {
            // Audit final pre-mainnet W34: build the Ogmara-channel alert
            // dispatcher when configured. Every failure mode here degrades
            // gracefully to `None` (alert dispatch just skips this one
            // channel) rather than failing node startup — same tolerance
            // as anchoring/IPFS misconfiguration elsewhere in this function.
            let channel_dispatcher = if self.config.alerts.ogmara_channel.enabled {
                match crate::notifications::alert_channel::load_alert_signing_key(
                    &self.config.alerts.ogmara_channel,
                ) {
                    Ok(Some(key)) => {
                        match crate::crypto::pubkey_to_address(&key.verifying_key()) {
                            Ok(derived_address)
                                if derived_address == self.config.alerts.ogmara_channel.wallet_address =>
                            {
                                Some(crate::notifications::alert_channel::AlertChannelDispatcher::new(
                                    self.storage.clone(),
                                    identity.clone(),
                                    gossip_tx.clone(),
                                    klever_network.clone(),
                                    key,
                                    derived_address,
                                    self.config.alerts.ogmara_channel.channel_id,
                                    network_counters.clone(),
                                ))
                            }
                            Ok(derived_address) => {
                                warn!(
                                    configured = %self.config.alerts.ogmara_channel.wallet_address,
                                    derived = %derived_address,
                                    "ogmara_channel alert signing key's derived address does not \
                                     match configured wallet_address — disabling this dispatch \
                                     channel rather than posting as the wrong identity"
                                );
                                None
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to derive address from ogmara_channel alert signing key");
                                None
                            }
                        }
                    }
                    Ok(None) => {
                        warn!(
                            "alerts.ogmara_channel.enabled = true but no signing key configured \
                             (set OGMARA_ALERT_SIGNING_KEY or signing_key_path) — disabling this \
                             dispatch channel"
                        );
                        None
                    }
                    Err(e) => {
                        warn!(error = %e, "failed to load ogmara_channel alert signing key — disabling this dispatch channel");
                        None
                    }
                }
            } else {
                None
            };

            // Code Audit WARNING #4: same "Klever configured" predicate
            // `ChainScanner::run` already uses to no-op an unconfigured
            // isolated-subnet node — gates `KleverDisconnected` so it can't
            // permanently false-positive on a node that never makes a
            // Klever RPC call in the first place.
            let klever_configured = !self.config.klever.node_url.is_empty()
                && !self.config.klever.api_url.is_empty()
                && !self.config.klever.contract_address.is_empty();
            let mut alert_engine =
                crate::notifications::alerts::AlertEngine::new(
                    self.config.alerts.clone(),
                    self.node_id.clone(),
                    alert_event_rx,
                    self.config.anchoring.interval_seconds,
                    channel_dispatcher,
                    klever_configured,
                );
            alert_engine.set_history(alert_history.clone());
            let alert_metrics = metrics_latest.clone();
            let alert_shutdown_rx = self.shutdown_rx();
            spawn_supervised("alert_engine", async move {
                alert_engine.run(alert_metrics, alert_shutdown_rx).await;
            });
            info!("Alert engine started");
        } else {
            // Explicit drop of the unused receiver so reviewers don't
            // wonder why it's unused. Channel sender clones already
            // gated on alerts.enabled => None upstream.
            drop(alert_event_rx);
        }
        // Suppress unused-warning on the always-allocated sender until
        // sc_discovery wiring lands later in this method.
        // SC peer-discovery background task (spec 13 §4.3 tier 3,
        // promoted to primary boot path in 0.46.5 per spec 13 §4.2).
        // Runs an immediate cold-start fan-out if the peer book is
        // below threshold, then a 1h-cadence steady-state refresh. In
        // pure-SC mode (`bootstrap_nodes = []`) the cold-start fan-out
        // retries every `retry_interval_secs` until a peer is found.
        //
        // Disabled cleanly when:
        //   - `[network.sc_discovery] enabled = false` (isolated subnet
        //     mode — operator opt-out; the config validator already
        //     rejects the both-empty case, so this implies non-empty
        //     `bootstrap_nodes`).
        //   - `klever.node_url` or `contract_address` are unset (no
        //     way to query the SC — the task warns and idles internally).
        //
        // Sender side of the reconnect channel is consumed here; the
        // matching receiver was attached to `network.run` earlier so
        // out-of-cycle dial-persisted-peers triggers fire within
        // seconds of a fresh persist.
        if !self.config.network.sc_discovery.enabled {
            // Isolated-subnet mode (spec 13 §4.2). Audit invariant:
            // no Klever API call paths for peer discovery in this
            // mode — log loudly so the operator sees confirmation.
            tracing::info!(
                bootstrap_nodes_count = self.config.network.bootstrap_nodes.len(),
                "sc_discovery: disabled by config (isolated subnet mode — \
                 the on-chain registry will NOT be queried for peer discovery)"
            );
        } else {
            let sc_disc_klever_url = self.config.klever.node_url.clone();
            let sc_disc_contract = self.config.klever.contract_address.clone();
            let sc_disc_storage = self.storage.clone();
            let sc_disc_self_addr = node_address.clone();
            let sc_disc_alert_tx = if self.config.alerts.enabled {
                Some(alert_event_tx.clone())
            } else {
                None
            };
            let sc_disc_shutdown_rx = self.shutdown_rx();
            let sc_disc_reconnect_tx = sc_reconnect_tx.clone();
            // Capture the staleness cutoff before the spawn so the async
            // block doesn't need `self`.
            let sc_disc_staleness_secs = (self.config.network.discovery.max_peer_staleness_days
                as u64)
                .saturating_mul(24 * 3600);
            let sc_disc_retry_interval = std::time::Duration::from_secs(
                self.config.network.sc_discovery.retry_interval_secs,
            );
            let sc_disc_bootstrap_empty = self.config.network.bootstrap_nodes.is_empty();
            let sc_disc_max_candidates =
                self.config.network.sc_discovery.max_candidates as usize;
            let sc_disc_klever_health = klever_health.clone();
            spawn_supervised("sc_discovery", async move {
                match crate::network::sc_discovery::ScDiscovery::new(
                    sc_disc_klever_url,
                    sc_disc_contract,
                    sc_disc_storage,
                    sc_disc_self_addr,
                    sc_disc_reconnect_tx,
                    sc_disc_alert_tx,
                    identify_success_count,
                    sc_added_peer_ids,
                    // Same staleness cutoff that `bootstrap-candidates`
                    // uses — spec 13 §7 mandates a single config-driven
                    // value across both consumers.
                    sc_disc_staleness_secs,
                    sc_disc_retry_interval,
                    sc_disc_bootstrap_empty,
                    sc_disc_max_candidates,
                    sc_disc_klever_health,
                ) {
                    Ok(disc) => disc.run(sc_disc_shutdown_rx).await,
                    Err(e) => warn!(error = %e, "Failed to start sc_discovery"),
                }
            });
        }
        // Suppress unused-warning on the original sender — we only
        // need the clone we passed to the task; the parent's copy
        // would just sit idle.
        drop(sc_reconnect_tx);
        let _ = &alert_event_tx;

        // Shared metadata-drift snapshot (spec 13 §6.1). Always
        // allocated so the `node_metadata` admin endpoint can read
        // unconditionally even when the reconciler is not spawned
        // (anchoring disabled or `[anchoring.metadata] publish =
        // false`). Reconciler — when spawned — is the sole writer.
        let metadata_drift_handle =
            crate::chain::metadata_reconcile::shared_metadata_drift();
        if self.config.anchoring.enabled && self.config.anchoring.metadata.publish {
            let recon_klever_url = self.config.klever.node_url.clone();
            let recon_contract = self.config.klever.contract_address.clone();
            let recon_node_addr = node_address.clone();
            let recon_metadata_cfg = self.config.anchoring.metadata.clone();
            let recon_listen_port = self.config.network.listen_port;
            let recon_peer_id = network_peer_id.clone();
            let recon_public_url = self.config.api.public_url.clone();
            let recon_tor_cfg = self.config.network.tor.clone();
            let recon_drift = metadata_drift_handle.clone();
            let recon_alert_tx = if self.config.alerts.enabled {
                Some(alert_event_tx.clone())
            } else {
                None
            };
            let recon_shutdown_rx = self.shutdown_rx();
            let recon_klever_health = klever_health.clone();
            spawn_supervised("metadata_reconciler", async move {
                match crate::chain::metadata_reconcile::MetadataReconciler::new(
                    recon_klever_url,
                    recon_contract,
                    recon_node_addr,
                    recon_metadata_cfg,
                    recon_listen_port,
                    recon_peer_id,
                    recon_public_url,
                    recon_tor_cfg,
                    recon_drift,
                    recon_alert_tx,
                    recon_klever_health,
                ) {
                    Ok(recon) => recon.run(recon_shutdown_rx).await,
                    Err(e) => warn!(error = %e, "Failed to start metadata_reconcile"),
                }
            });
        } else {
            debug!(
                anchoring_enabled = self.config.anchoring.enabled,
                publish_enabled = self.config.anchoring.metadata.publish,
                "metadata_reconcile not spawned (anchoring or publish disabled)"
            );
        }

        // Resolve media-handler tuning from IpfsConfig. Anything the
        // operator left at default in ogmara.toml falls through to
        // `default_media_*` (see `config.rs`). Conversion to bytes is
        // saturating to guard against absurd config; values are also
        // validated at config-load time (`Config::validate`) so this
        // is double protection.
        //
        // `usize::try_from` is the 32-bit-correct cast (audit warning
        // W-3 security). On 64-bit targets it's a no-op; on 32-bit it
        // saturates at usize::MAX rather than silently truncating the
        // high bits to zero.
        let media_tuning = crate::api::state::MediaTuning {
            cache_total_bytes: self
                .config
                .ipfs
                .media_cache_total_mb
                .saturating_mul(1024 * 1024),
            cache_item_bytes: usize::try_from(self.config.ipfs.media_cache_item_mb)
                .unwrap_or(usize::MAX)
                .saturating_mul(1024 * 1024),
            handler_permits: self.config.ipfs.media_handler_permits,
            per_ip_permits: self.config.ipfs.media_per_ip_permits,
            max_tracked_ips: self.config.ipfs.media_max_tracked_ips,
        };
        // Build trusted-proxy set (v0.42). Config-load already
        // validated parseability; `expect` is safe because the
        // validate() pass would have aborted startup on any bad entry.
        let trusted_proxies = Arc::new(
            crate::trusted_proxies::TrustedProxies::from_strings(
                &self.config.api.trusted_proxies,
            )
            .expect("trusted_proxies validated at config load"),
        );
        let app_state = Arc::new(crate::api::state::AppState::with_broadcast(
            self.storage.clone(),
            api_router,
            self.node_id.clone(),
            klever_network,
            self.config.klever.node_url.clone(),
            self.config.klever.contract_address.clone(),
            ipfs_client,
            identity.clone(),
            self.config.api.public_url.clone(),
            notification_engine.clone(),
            ws_broadcast,
            anchor_trigger_tx,
            peer_count,
            gossip_tx,
            identity_sync_tx,
            dm_subscribe_tx,
            channel_subscribe_tx,
            connected_peers,
            network_counters,
            metrics_latest,
            metrics_history,
            alert_history,
            pow_manager.clone(),
            node_address.clone(),
            snapshot_cache.clone(),
            media_tuning,
            trusted_proxies,
            anchor_divergence_counter,
            anchor_canonical_counter,
            self.config.network.listen_port,
            network_peer_id,
            self.config.anchoring.metadata.clone(),
            self.config.anchoring.pause_on_shutdown,
            // True if a key is configured either in the config file
            // (legacy / non-recommended) or via the env var (preferred,
            // per AnchoringConfig.wallet_key doc). Read-only check —
            // the key itself never lands on AppState. Uses
            // `wallet_key_hex().is_some()` which returns true iff the
            // SecretString-wrapped field deserialized to non-empty
            // (custom deserializer normalises empty string to None).
            self.config.anchoring.wallet_key_hex().is_some()
                || std::env::var("OGMARA_ANCHOR_WALLET_KEY")
                    .map(|v| !v.is_empty())
                    .unwrap_or(false),
            // [network.discovery] max_peer_staleness_days converted to
            // seconds. Saturating mul guards against an absurd operator
            // config (e.g. u32::MAX days). Default 7 days = 604_800s.
            (self.config.network.discovery.max_peer_staleness_days as u64)
                .saturating_mul(24 * 3600),
            // [network] bootstrap_nodes — feeds the tier-2 source in
            // bootstrap-candidates union (spec 13 §4.5). Cloned once;
            // operators restart to change.
            self.config.network.bootstrap_nodes.clone(),
            // [network.sc_discovery] enabled — when false (isolated
            // subnet mode, spec 13 §4.2), the bootstrap-candidates
            // handler skips tier-3 entirely so no Klever SC views
            // are called from the discovery path. Audit invariant
            // for the politically-resilient operator profile.
            self.config.network.sc_discovery.enabled,
            // Shared drift snapshot — written by the
            // `metadata_reconcile` task (when spawned), read by the
            // `node_metadata` admin endpoint. Always allocated even
            // when the reconciler is not spawned so the admin
            // endpoint can read unconditionally.
            metadata_drift_handle.clone(),
            // Spec 10 §9.2 — B4 instrumentation surface. Shared with
            // `NetworkService`; written every 30s by the network task,
            // read by the `/admin/network/mesh-stats` endpoint.
            mesh_stats_handle.clone(),
            publish_failure_counters.clone(),
            // Spec 3 §media-fetch (l2-node 0.46.7+) — peer-fallback
            // state. Built only when both Klever wiring is set AND
            // the operator enabled `[media] peer_fallback_enabled`.
            // The state owns its own reqwest::Client (separate
            // timeouts and policy from the rest of the node) and a
            // global concurrent-fanout semaphore.
            if self.config.media.peer_fallback_enabled
                && !self.config.klever.node_url.is_empty()
                && !self.config.klever.contract_address.is_empty()
            {
                let staleness_secs = (self
                    .config
                    .network
                    .discovery
                    .max_peer_staleness_days as u64)
                    .saturating_mul(24 * 3600);
                match crate::api::media_fallback::MediaFallbackState::new(
                    self.config.media.clone(),
                    node_address.clone(),
                    self.config.klever.node_url.clone(),
                    self.config.klever.contract_address.clone(),
                    staleness_secs,
                ) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        warn!(
                            error = %e,
                            "media-fallback init failed; disabling fallback"
                        );
                        None
                    }
                }
            } else {
                None
            },
            // Spec 13 §6.4 — onion-transport config snapshot. Cloned
            // into AppState so the `node_metadata` admin endpoint can
            // append the onion multiaddr to the desired list when
            // `advertise_onion_in_metadata = true`.
            self.config.network.tor.clone(),
            // Spec 13 §10 — presence-gossip manager handle. `Some`
            // iff `[network.presence] enabled = true`. Drives the
            // `/api/v1/network/presence*` REST surface.
            presence_manager_handle.clone(),
            // [network] network_id snapshot — exposed via
            // /api/v1/network/identity (spec 03 §4.1).
            self.config.network_id().to_string(),
            // governance-dashboard-plan.md Phase 6 — channel to submit
            // arbitrary governance SC-invoke calldata for server-side
            // signing by the anchoring task's wallet. `None` when
            // anchoring is disabled (no signing key loaded).
            governance_submit_tx,
            // The klv1... address that will actually sign governance
            // TXs — distinct from `node_address` when a separate
            // `[anchoring] wallet_key` is configured. `None` when
            // anchoring is disabled.
            anchor_wallet_address,
        ));
        // Background sweep: drop zero-counter entries from the per-IP
        // media limiter (v0.41). Without this, the DashMap accumulates
        // an entry per IP that ever hit the media endpoint — under an
        // IP-rotating attacker this grows unboundedly. Runs every 5
        // minutes; that's slow enough to be negligible CPU but fast
        // enough to keep memory bounded under sustained attack.
        // JoinHandle dropped immediately — the spawned task lives via
        // its own tokio task slot and exits on shutdown_rx signal.
        // No need to await it during graceful shutdown; the sweep
        // doesn't hold any resources that must be flushed.
        let _ = supervise_handle(
            "media_limiter_sweep",
            app_state
                .media_limiter
                .clone()
                .spawn_sweep_task(std::time::Duration::from_secs(300), self.shutdown_rx()),
        );

        // Periodic cleanup task: evict stale rate limit entries and expired PoW challenges.
        // Runs every 5 minutes to prevent unbounded memory growth.
        let cleanup_state = app_state.clone();
        let mut cleanup_shutdown_rx = self.shutdown_rx();
        let cleanup_task = spawn_supervised("periodic_cleanup", async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Clean up stale per-user rate limit entries
                        cleanup_state.router.cleanup_rate_limits();
                        // Clean up expired PoW challenges
                        if let Some(ref pow) = cleanup_state.pow {
                            pow.cleanup_expired_challenges();
                        }
                    }
                    _ = cleanup_shutdown_rx.recv() => break,
                }
            }
        });

        // Notification retention reaper (audit final pre-mainnet W31):
        // own interval, not folded into the cleanup task above — that
        // one only touches cheap in-memory maps, this does real batched
        // RocksDB deletion work (same reasoning as the DM reaper, W11).
        let notification_reap_storage = self.storage.clone();
        let notification_retention_days = self.config.notifications.retention_days;
        let notification_reap_interval_secs = self.config.notifications.reap_interval_secs;
        let mut notification_reap_shutdown_rx = self.shutdown_rx();
        spawn_supervised("notification_reaper", async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                notification_reap_interval_secs.max(1),
            ));
            interval.tick().await; // skip immediate tick
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        reap_expired_notifications(&notification_reap_storage, notification_retention_days);
                    }
                    _ = notification_reap_shutdown_rx.recv() => break,
                }
            }
        });

        // Device-enc-key tombstone reaper (audit final pre-mainnet W15):
        // own interval, same reasoning as the notification reaper above.
        let device_enc_reap_storage = self.storage.clone();
        let device_enc_tombstone_retention_days =
            self.config.device_enc.tombstone_retention_days;
        let device_enc_reap_interval_secs = self.config.device_enc.reap_interval_secs;
        let mut device_enc_reap_shutdown_rx = self.shutdown_rx();
        spawn_supervised("device_enc_tombstone_reaper", async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                device_enc_reap_interval_secs.max(1),
            ));
            interval.tick().await; // skip immediate tick
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        reap_device_enc_tombstones(&device_enc_reap_storage, device_enc_tombstone_retention_days);
                    }
                    _ = device_enc_reap_shutdown_rx.recv() => break,
                }
            }
        });

        // Pending-channel-delete-claim reaper (audit final pre-mainnet W14):
        // own interval, same reasoning as the reapers above.
        let channel_delete_reap_storage = self.storage.clone();
        let channel_delete_pending_retention_hours =
            self.config.channel_delete.pending_retention_hours;
        let channel_delete_reap_interval_secs = self.config.channel_delete.reap_interval_secs;
        let mut channel_delete_reap_shutdown_rx = self.shutdown_rx();
        spawn_supervised("channel_delete_claim_reaper", async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                channel_delete_reap_interval_secs.max(1),
            ));
            interval.tick().await; // skip immediate tick
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        reap_channel_delete_claims(&channel_delete_reap_storage, channel_delete_pending_retention_hours);
                    }
                    _ = channel_delete_reap_shutdown_rx.recv() => break,
                }
            }
        });

        // Pending-channel-member-removal-claim reaper (W18 residual, found +
        // fixed 2026-08-19): own interval, same reasoning as the reapers above.
        let channel_member_removal_reap_storage = self.storage.clone();
        let channel_member_removal_pending_retention_hours =
            self.config.channel_member_removal.pending_retention_hours;
        let channel_member_removal_reap_interval_secs =
            self.config.channel_member_removal.reap_interval_secs;
        let mut channel_member_removal_reap_shutdown_rx = self.shutdown_rx();
        spawn_supervised("channel_member_removal_claim_reaper", async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                channel_member_removal_reap_interval_secs.max(1),
            ));
            interval.tick().await; // skip immediate tick
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        reap_channel_member_removal_claims(
                            &channel_member_removal_reap_storage,
                            channel_member_removal_pending_retention_hours,
                        );
                    }
                    _ = channel_member_removal_reap_shutdown_rx.recv() => break,
                }
            }
        });

        let api_config = self.config.clone();
        let api_shutdown_rx = self.shutdown_rx();
        let mut api_task = tokio::spawn(async move {
            if let Err(e) = crate::api::start_api_server(&api_config, app_state, api_shutdown_rx).await {
                tracing::error!(error = %e, "API server error");
            }
        });

        // Wait for shutdown signal — SIGINT (Ctrl+C) or, on Unix,
        // SIGTERM (systemd / docker stop). Both flow through the same
        // shutdown_tx broadcast so every task observes the same
        // shutdown event. The dedicated SIGTERM arm matters for
        // v0.45.0's `pause_on_shutdown` flow because systemd sends
        // SIGTERM (not SIGINT) by default.
        let mut shutdown_rx = self.shutdown_rx();
        #[cfg(unix)]
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )
        .context("registering SIGTERM handler")?;
        // Spec Compliance follow-up (W17): set on a critical-task fail-fast
        // branch below, checked at the end of this function. Falling
        // through the SAME cleanup sequence as a normal shutdown but then
        // returning `Err` (rather than `Ok(())`) is what makes `main.rs`'s
        // `#[tokio::main] async fn main() -> Result<()>` exit non-zero —
        // required for `systemd`'s `Restart=on-failure` to actually
        // restart the node. A first cut of this fix logged the failure but
        // still returned `Ok(())`, meaning the process exited 0 — clean-
        // shutdown-shaped, so `Restart=on-failure` would NOT have
        // restarted it (that directive only fires on non-zero exit / an
        // abnormal signal), silently defeating this entire fix's premise
        // on the systemd deployment (Docker's `restart: unless-stopped`
        // restarts regardless of exit code, so that path was unaffected).
        let mut critical_task_failure: Option<String> = None;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT (Ctrl+C), shutting down...");
            }
            _ = async {
                #[cfg(unix)]
                {
                    let _ = sigterm.recv().await;
                }
                #[cfg(not(unix))]
                {
                    std::future::pending::<()>().await;
                }
            } => {
                info!("Received SIGTERM, shutting down...");
            }
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received");
            }
            // W17 (audit final pre-mainnet, l2-node 0.102.0+): fail fast if
            // a CRITICAL subsystem task exits unexpectedly — panic or an
            // early return that isn't the normal shutdown path. Without
            // this, e.g. a panic inside `NetworkService::run` silently
            // killed gossip/federation/backfill while REST/`/health` kept
            // reporting "ok" and `peer_count` (written only by that task)
            // froze — a "zombie node" invisible to monitoring on an
            // unattended mainnet deployment. Falling through into the same
            // unconditional shutdown/cleanup sequence below (rather than a
            // separate code path) relies on both fleet deployment modes
            // (systemd, Docker) restarting on process exit — a hard exit
            // is also a strictly stronger signal (connection refused) than
            // a `/health` flag a monitor might not be checking. Recording
            // into `critical_task_failure` (checked at the end of this
            // function) is what actually makes that exit non-zero.
            // `&mut task` (not consuming the handle) matters: the existing
            // `.abort()` calls below still run on whichever handle DIDN'T
            // fire this branch, and calling `.abort()` on the one that DID
            // is a harmless no-op on an already-completed task.
            result = &mut network_task => {
                let reason = match result {
                    Ok(()) => "network task exited unexpectedly (not via shutdown)".to_string(),
                    Err(e) => format!("network task panicked: {e}"),
                };
                error!(%reason, "shutting down");
                critical_task_failure = Some(reason);
            }
            result = &mut chain_task => {
                let reason = match result {
                    Ok(()) => "chain scanner task exited unexpectedly (not via shutdown)".to_string(),
                    Err(e) => format!("chain scanner task panicked: {e}"),
                };
                error!(%reason, "shutting down");
                critical_task_failure = Some(reason);
            }
            result = &mut api_task => {
                let reason = match result {
                    Ok(()) => "API server task exited unexpectedly (not via shutdown)".to_string(),
                    Err(e) => format!("API server task panicked: {e}"),
                };
                error!(%reason, "shutting down");
                critical_task_failure = Some(reason);
            }
        }

        self.shutdown();

        // Persist final Lamport counter
        let val = self.lamport_counter.load(Ordering::SeqCst);
        self.storage.set_lamport_counter(val)?;

        // Give the anchor task a bounded window to broadcast its
        // graceful `pauseNode` (v0.45.0 spec 13 §6.3) before we abort.
        // 45s covers the worst-case 4-step Klever RPC chain (nonce +
        // send + decode + broadcast) — each call has its own 15s
        // reqwest timeout, so the chain can take up to 60s, but the
        // SIGTERM-pause is best-effort and overflow is acceptable.
        // Widened from 20s after Security Audit W4 flagged the
        // 20s/15s-per-call inconsistency.
        if let Some(handle) = anchor_task.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(45), handle).await {
                Ok(Ok(())) => debug!("Anchor task finished cleanly on shutdown"),
                Ok(Err(e)) => warn!(error = %e, "Anchor task panicked on shutdown"),
                Err(elapsed) => {
                    // The handle was moved into timeout(); on timeout
                    // it's dropped, NOT aborted. Drop alone doesn't
                    // cancel a tokio task. So we can't abort from
                    // here — log truthfully instead (Code Audit W2).
                    warn!(
                        elapsed = ?elapsed,
                        "Anchor task did not finish within 45s; continuing shutdown — \
                         task may still be in flight, will be killed when the process exits"
                    );
                }
            }
        }

        lamport_task.abort();
        cleanup_task.abort();
        network_task.abort();
        chain_task.abort();
        api_task.abort();

        info!("Node stopped");
        // W17: an unexpected critical-task death must produce a non-zero
        // process exit (`main.rs`'s `#[tokio::main] async fn main() ->
        // Result<()>` turns a returned `Err` into exit code 1) — a clean
        // `Ok(())` here would be indistinguishable from a normal SIGINT/
        // SIGTERM shutdown to `systemd`'s `Restart=on-failure`, which does
        // NOT restart on exit code 0. See the comment on
        // `critical_task_failure`'s declaration above.
        match critical_task_failure {
            Some(reason) => anyhow::bail!("critical subsystem task failed: {reason}"),
            None => Ok(()),
        }
    }
}

/// Load the node's Ed25519 signing key from storage, or generate a new one.
fn load_or_generate_key(storage: &Storage) -> Result<SigningKey> {
    match storage.get_cf(
        crate::storage::schema::cf::NODE_STATE,
        state_keys::NODE_PRIVATE_KEY,
    )? {
        Some(mut bytes) if bytes.len() == 32 => {
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            let key = SigningKey::from_bytes(&key_bytes);
            // Zeroize both copies of the raw private key — the storage
            // Vec and the intermediate stack array. `SigningKey` itself
            // is ZeroizeOnDrop per ed25519-dalek 2.x (Phase C Security
            // Audit N2 sibling-site fix).
            bytes.fill(0);
            key_bytes.fill(0);
            info!("Loaded existing node identity key");
            Ok(key)
        }
        _ => {
            let key = crypto::generate_keypair();
            storage.put_cf(
                crate::storage::schema::cf::NODE_STATE,
                state_keys::NODE_PRIVATE_KEY,
                key.as_bytes(),
            )?;
            info!("Generated new node identity key");
            Ok(key)
        }
    }
}

/// Detect and recover from a half-applied snapshot bootstrap (Phase 2).
///
/// On boot, if `SNAPSHOT_ROLLBACK_DIR` is set in NODE_STATE but
/// `SNAPSHOT_APPLIED_AT_HEIGHT` is absent, the previous apply crashed
/// between starting the destructive ops and writing the success
/// sentinel. We restore by:
///   1. Closing the current Storage handle.
///   2. Renaming `data/db` → `data/db_failed_apply_<ts>` (preserves
///      forensics; operator can rm later).
///   3. Renaming the rollback dir → `data/db`.
///   4. Reopening Storage from the restored dir.
///   5. Clearing `SNAPSHOT_ROLLBACK_DIR` so the next boot is clean.
///
/// If the rollback dir doesn't exist on disk (operator deleted it,
/// disk failure, etc.) we refuse to boot with a clear error rather
/// than silently start with a corrupt DB.
///
/// Returns the (possibly recovered) Storage handle.
fn check_snapshot_apply_recovery(storage: Storage, db_path: &std::path::Path) -> Result<Storage> {
    use crate::storage::schema::{cf, state_keys};

    let rollback_raw = storage
        .get_cf(cf::NODE_STATE, state_keys::SNAPSHOT_ROLLBACK_DIR)
        .context("reading SNAPSHOT_ROLLBACK_DIR")?;
    let Some(rollback_bytes) = rollback_raw else {
        return Ok(storage); // No rollback marker — nothing to do.
    };
    if rollback_bytes.is_empty() {
        return Ok(storage); // Cleared marker.
    }

    let sentinel_present = storage
        .get_cf(cf::NODE_STATE, state_keys::SNAPSHOT_APPLIED_AT_HEIGHT)
        .context("reading SNAPSHOT_APPLIED_AT_HEIGHT")?
        .is_some();

    if sentinel_present {
        // Apply completed successfully; the rollback dir is just lingering.
        // Clear the marker (the dir itself stays on disk until the scanner
        // catches up — Phase 3 will GC it).
        warn!(
            "Found lingering SNAPSHOT_ROLLBACK_DIR with sentinel present — clearing marker (apply was successful)"
        );
        storage
            .delete_cf(cf::NODE_STATE, state_keys::SNAPSHOT_ROLLBACK_DIR)
            .context("clearing stale SNAPSHOT_ROLLBACK_DIR marker")?;
        return Ok(storage);
    }

    // CRASHED APPLY — perform restore.
    let rollback_path_str = String::from_utf8(rollback_bytes)
        .context("SNAPSHOT_ROLLBACK_DIR is not valid UTF-8")?;
    let rollback_path = std::path::PathBuf::from(&rollback_path_str);
    if !rollback_path.exists() {
        anyhow::bail!(
            "Crashed snapshot apply detected (SNAPSHOT_ROLLBACK_DIR={} but \
             sentinel absent) AND rollback directory no longer exists. \
             Manual recovery required. See tests/integration/SNAPSHOT_BOOTSTRAP.md.",
            rollback_path.display()
        );
    }

    warn!(
        rollback_dir = %rollback_path.display(),
        "Crashed snapshot apply detected — restoring from rollback checkpoint"
    );

    // 1. Close the current DB handle.
    drop(storage);

    // 2. Move the (corrupt) DB aside for forensics.
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let corrupt_path = db_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("db_path has no parent"))?
        .join(format!("db_failed_apply_{}", ts_ms));
    std::fs::rename(db_path, &corrupt_path)
        .with_context(|| format!("moving corrupt db to {}", corrupt_path.display()))?;

    // 3. Promote the rollback checkpoint to the live DB location.
    std::fs::rename(&rollback_path, db_path).with_context(|| {
        format!(
            "promoting rollback checkpoint {} to {}",
            rollback_path.display(),
            db_path.display()
        )
    })?;

    // 4. Reopen Storage from the restored dir.
    let storage = Storage::open(db_path).context("reopening RocksDB after rollback restore")?;

    // 5. Clear the marker.
    storage
        .delete_cf(cf::NODE_STATE, state_keys::SNAPSHOT_ROLLBACK_DIR)
        .context("clearing SNAPSHOT_ROLLBACK_DIR after restore")?;

    info!(
        forensics_dir = %corrupt_path.display(),
        "Snapshot apply rollback complete — corrupt DB preserved for inspection (safe to delete after review)"
    );

    Ok(storage)
}

#[cfg(test)]
mod supervised_task_tests {
    //! Audit final pre-mainnet W17. `spawn_supervised`/`supervise_handle`'s
    //! entire correctness rests on `JoinError::is_cancelled()` correctly
    //! distinguishing an intentional `.abort()` (must NOT be logged as a
    //! panic — every task is `.abort()`'d during normal shutdown) from a
    //! genuine panic (must be logged). Prove that distinction directly
    //! against real tokio tasks, rather than assuming library behavior.
    use super::*;

    #[tokio::test]
    async fn genuine_panic_is_not_reported_as_cancelled() {
        let handle = tokio::spawn(async {
            panic!("boom");
        });
        let err = handle.await.expect_err("a panicking task must yield Err(JoinError)");
        assert!(!err.is_cancelled(), "a genuine panic must not be classified as a cancellation");
    }

    #[tokio::test]
    async fn intentional_abort_is_reported_as_cancelled() {
        let handle = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        handle.abort();
        let err = handle.await.expect_err("an aborted task must yield Err(JoinError)");
        assert!(err.is_cancelled(), "an intentional .abort() must be classified as a cancellation, never logged as a panic");
    }

    #[tokio::test]
    async fn spawn_supervised_abort_handle_can_still_abort_the_task() {
        // Confirms the AbortHandle returned by spawn_supervised (not the
        // JoinHandle, which the internal watcher task owns) genuinely
        // controls the underlying task — this is the property
        // `lamport_task.abort()`/`cleanup_task.abort()` at shutdown rely on.
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran2 = ran.clone();
        let abort_handle = spawn_supervised("test_task", async move {
            std::future::pending::<()>().await;
            // Unreachable unless the abort fails to take effect.
            ran2.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        abort_handle.abort();
        // Give the runtime a moment to actually process the abort.
        tokio::task::yield_now().await;
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
        assert!(abort_handle.is_finished());
    }
}

#[cfg(test)]
mod notification_reaper_tests {
    //! Audit final pre-mainnet W31. Covers the pure planning logic
    //! factored out of `reap_expired_notifications` — see the note on
    //! `plan_notification_reap` for why the I/O shell itself isn't
    //! tested directly here (same swarm/live-Storage testing gap as the
    //! W11 DM reaper).
    use super::*;

    fn notification_row(address: &str, ts: u64, id: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        (
            crate::storage::schema::encode_notification_key(address, ts, &id),
            Vec::new(),
        )
    }

    #[test]
    fn deletes_only_expired_rows() {
        let rows = vec![
            notification_row("klv1alice", 100, [1u8; 32]), // expired
            notification_row("klv1alice", 200, [2u8; 32]), // not expired
            notification_row("klv1bob", 50, [3u8; 32]),    // expired
        ];
        let (to_delete, next_cursor) = plan_notification_reap(&rows, 150, 100);
        assert_eq!(to_delete.len(), 2);
        assert!(to_delete.contains(&rows[0].0));
        assert!(to_delete.contains(&rows[2].0));
        assert!(!to_delete.contains(&rows[1].0));
        assert!(next_cursor.is_some());
    }

    #[test]
    fn respects_batch_limit_and_cursor_never_skips_an_unexamined_row() {
        // Regression for the exact class of bug the W11 DM reaper's
        // post-fix Code Audit caught: the cursor must resume from the
        // LAST EXAMINED row, never an unexamined one skipped by the
        // batch-limit break.
        let rows: Vec<_> = (0..10)
            .map(|i| notification_row("klv1alice", 0, [i as u8; 32])) // all expired
            .collect();
        let (to_delete, next_cursor) = plan_notification_reap(&rows, 1000, 3);
        assert_eq!(to_delete.len(), 3);
        let expected_cursor = {
            let mut c = rows[2].0.clone();
            c.push(0);
            c
        };
        assert_eq!(next_cursor, Some(expected_cursor));
    }

    #[test]
    fn handles_variable_length_addresses() {
        // Klever addresses are a fixed-format bech32 string in practice,
        // but the key encoding doesn't assume a fixed length (W11
        // lesson) — prove both a short and a long address parse
        // correctly via the same 0xFF-delimited, length-derived-from-end
        // logic.
        let rows = vec![
            notification_row("klv1short", 100, [1u8; 32]),
            notification_row(&format!("klv1{}", "a".repeat(58)), 100, [2u8; 32]),
        ];
        let (to_delete, _) = plan_notification_reap(&rows, 150, 100);
        assert_eq!(to_delete.len(), 2, "both address lengths must be reaped correctly");
    }

    #[test]
    fn empty_batch_returns_none_cursor() {
        let (to_delete, next_cursor) = plan_notification_reap(&[], 1000, 100);
        assert!(to_delete.is_empty());
        assert!(next_cursor.is_none());
    }

    #[test]
    fn cursor_advances_even_when_nothing_deleted() {
        let rows = vec![notification_row("klv1alice", 999_999, [9u8; 32])]; // not expired
        let (to_delete, next_cursor) = plan_notification_reap(&rows, 100, 100);
        assert!(to_delete.is_empty());
        let cursor = next_cursor.expect("cursor must still advance to make forward progress");
        assert!(cursor > rows[0].0);
    }
}

#[cfg(test)]
mod device_enc_tombstone_reaper_tests {
    //! Audit final pre-mainnet W15. Covers the pure planning logic
    //! factored out of `reap_device_enc_tombstones`. The single most
    //! important property tested here: an ACTIVE key (`"revoked": false`)
    //! must NEVER be deleted, regardless of age — unlike the DM/
    //! notification reapers, a bug here would be a real security
    //! regression (breaking device encryption), not just a missed
    //! cleanup.
    use super::*;

    fn row(wallet: &str, enc_pub: &str, value: serde_json::Value) -> (Vec<u8>, Vec<u8>) {
        (
            crate::storage::schema::encode_device_enc_key(wallet, enc_pub),
            serde_json::to_vec(&value).unwrap(),
        )
    }

    fn active(ts: u64) -> serde_json::Value {
        serde_json::json!({"ts": ts, "revoked": false})
    }
    fn revoked(ts: u64) -> serde_json::Value {
        serde_json::json!({"ts": ts, "revoked": true})
    }

    #[test]
    fn deletes_only_revoked_and_expired_rows() {
        let rows = vec![
            row("klv1alice", "enc1", revoked(100)), // revoked + expired
            row("klv1alice", "enc2", revoked(200)), // revoked, not expired
            row("klv1alice", "enc3", active(50)),   // active + "expired" ts, must survive
        ];
        let (to_delete, _) = plan_device_enc_tombstone_reap(&rows, 150, 100);
        assert_eq!(to_delete.len(), 1);
        assert_eq!(to_delete[0], rows[0].0);
    }

    #[test]
    fn never_deletes_an_active_key_regardless_of_age() {
        // The one property this reaper must never get wrong: an active
        // binding has no TTL, full stop.
        let rows = vec![row("klv1alice", "enc1", active(0))]; // ts=0, oldest possible
        let (to_delete, _) = plan_device_enc_tombstone_reap(&rows, u64::MAX, 100);
        assert!(to_delete.is_empty(), "an active key must never be reaped, no matter how old");
    }

    #[test]
    fn missing_or_malformed_revoked_field_defaults_to_never_delete() {
        // Absent/malformed "revoked" must be treated as "not revoked" (fail
        // safe toward NOT deleting), not as revoked.
        let rows = vec![
            (
                crate::storage::schema::encode_device_enc_key("klv1alice", "enc1"),
                serde_json::to_vec(&serde_json::json!({"ts": 0})).unwrap(), // no "revoked" key
            ),
        ];
        let (to_delete, _) = plan_device_enc_tombstone_reap(&rows, u64::MAX, 100);
        assert!(to_delete.is_empty());
    }

    #[test]
    fn respects_batch_limit_and_cursor_never_skips_an_unexamined_row() {
        let rows: Vec<_> = (0..10)
            .map(|i| row("klv1alice", &format!("enc{i}"), revoked(0))) // all revoked+expired
            .collect();
        let (to_delete, next_cursor) = plan_device_enc_tombstone_reap(&rows, 1000, 3);
        assert_eq!(to_delete.len(), 3);
        let expected_cursor = {
            let mut c = rows[2].0.clone();
            c.push(0);
            c
        };
        assert_eq!(next_cursor, Some(expected_cursor));
    }

    #[test]
    fn empty_batch_returns_none_cursor() {
        let (to_delete, next_cursor) = plan_device_enc_tombstone_reap(&[], 1000, 100);
        assert!(to_delete.is_empty());
        assert!(next_cursor.is_none());
    }

    #[test]
    fn cursor_advances_even_when_nothing_deleted() {
        let rows = vec![row("klv1alice", "enc1", active(999_999))];
        let (to_delete, next_cursor) = plan_device_enc_tombstone_reap(&rows, 100, 100);
        assert!(to_delete.is_empty());
        let cursor = next_cursor.expect("cursor must still advance to make forward progress");
        assert!(cursor > rows[0].0);
    }
}

#[cfg(test)]
mod channel_delete_claim_reaper_tests {
    //! Audit final pre-mainnet W14. Covers the pure planning logic factored
    //! out of `reap_channel_delete_claims`. Unlike the device-enc reaper,
    //! there's no never-delete invariant here — an expired unclaimed
    //! pending row is safe to drop unconditionally.
    use super::*;

    fn row(channel_id: u64, claimant: &str, requested_at: u64) -> (Vec<u8>, Vec<u8>) {
        (
            channel_id.to_be_bytes().to_vec(),
            serde_json::to_vec(&serde_json::json!({
                "claimant": claimant,
                "requested_at": requested_at,
            }))
            .unwrap(),
        )
    }

    #[test]
    fn deletes_only_expired_rows() {
        let rows = vec![
            row(1, "klv1alice", 100), // expired
            row(2, "klv1bob", 200),   // not expired
        ];
        let (to_delete, _) = plan_channel_delete_claim_reap(&rows, 150, 100);
        assert_eq!(to_delete.len(), 1);
        assert_eq!(to_delete[0], rows[0].0);
    }

    #[test]
    fn missing_or_malformed_requested_at_defaults_to_never_delete() {
        let rows = vec![(
            1u64.to_be_bytes().to_vec(),
            serde_json::to_vec(&serde_json::json!({"claimant": "klv1alice"})).unwrap(),
        )];
        let (to_delete, _) = plan_channel_delete_claim_reap(&rows, u64::MAX, 100);
        assert!(to_delete.is_empty());
    }

    #[test]
    fn respects_batch_limit_and_cursor_never_skips_an_unexamined_row() {
        let rows: Vec<_> = (0..10u64).map(|i| row(i, "klv1alice", 0)).collect();
        let (to_delete, next_cursor) = plan_channel_delete_claim_reap(&rows, 1000, 3);
        assert_eq!(to_delete.len(), 3);
        let expected_cursor = {
            let mut c = rows[2].0.clone();
            c.push(0);
            c
        };
        assert_eq!(next_cursor, Some(expected_cursor));
    }

    #[test]
    fn empty_batch_returns_none_cursor() {
        let (to_delete, next_cursor) = plan_channel_delete_claim_reap(&[], 1000, 100);
        assert!(to_delete.is_empty());
        assert!(next_cursor.is_none());
    }

    #[test]
    fn cursor_advances_even_when_nothing_deleted() {
        let rows = vec![row(1, "klv1alice", 999_999)];
        let (to_delete, next_cursor) = plan_channel_delete_claim_reap(&rows, 100, 100);
        assert!(to_delete.is_empty());
        let cursor = next_cursor.expect("cursor must still advance to make forward progress");
        assert!(cursor > rows[0].0);
    }
}

#[cfg(test)]
mod channel_member_removal_reaper_tests {
    //! W18 residual, found + fixed 2026-08-19. Covers the pure planning
    //! logic factored out of `reap_channel_member_removal_claims`. Same
    //! shape as `channel_delete_claim_reaper_tests`, except the value is a
    //! raw 8-byte BE timestamp (no JSON) — see
    //! `PENDING_CHANNEL_MEMBER_REMOVALS`'s schema doc comment.
    use super::*;

    fn row(channel_id: u64, address: &str, requested_at: u64) -> (Vec<u8>, Vec<u8>) {
        (
            crate::storage::schema::encode_channel_member_key(channel_id, address),
            requested_at.to_be_bytes().to_vec(),
        )
    }

    #[test]
    fn deletes_only_expired_rows() {
        let rows = vec![
            row(1, "klv1alice", 100), // expired
            row(1, "klv1bob", 200),   // not expired
        ];
        let (to_delete, _) = plan_channel_member_removal_reap(&rows, 150, 100);
        assert_eq!(to_delete.len(), 1);
        assert_eq!(to_delete[0], rows[0].0);
    }

    #[test]
    fn malformed_value_is_skipped_never_deleted() {
        let rows = vec![(
            crate::storage::schema::encode_channel_member_key(1, "klv1alice"),
            b"not-8-bytes".to_vec(),
        )];
        let (to_delete, _) = plan_channel_member_removal_reap(&rows, u64::MAX, 100);
        assert!(to_delete.is_empty());
    }

    #[test]
    fn respects_batch_limit_and_cursor_never_skips_an_unexamined_row() {
        let rows: Vec<_> = (0..10u64)
            .map(|i| row(1, &format!("klv1addr{i}"), 0))
            .collect();
        let (to_delete, next_cursor) = plan_channel_member_removal_reap(&rows, 1000, 3);
        assert_eq!(to_delete.len(), 3);
        let expected_cursor = {
            let mut c = rows[2].0.clone();
            c.push(0);
            c
        };
        assert_eq!(next_cursor, Some(expected_cursor));
    }

    #[test]
    fn empty_batch_returns_none_cursor() {
        let (to_delete, next_cursor) = plan_channel_member_removal_reap(&[], 1000, 100);
        assert!(to_delete.is_empty());
        assert!(next_cursor.is_none());
    }
}
