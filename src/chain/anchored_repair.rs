//! Anchored-state repair sweep (l2-node 0.148.0, spec 03 §3.2).
//!
//! The chain scanner keeps `ANCHORED_STATE` in step with new SC
//! transactions, but it cannot fill in what it never saw: history from
//! before this release, recorded scan gaps, ranges the Klever API can no
//! longer reach, changes it missed, and anything a downgraded node skipped.
//! This sweep closes those holes. Any source may PROPOSE a record — the
//! chain's own channel id space, the scanner-owned `DELEGATIONS` rows,
//! wallets in `USERS`, and other nodes' sealed mirrors (fetched over the
//! snapshot protocol) — but nothing enters or changes the mirror unless SC
//! views CONFIRM it.
//!
//! **Determinism** (two nodes that saw the same chain must seal the same
//! root): every repair write — inserting a missing record or correcting an
//! existing row — needs two sightings of the same SC value with our own row
//! unchanged in between. A working tick first checks the Klever node has
//! reached our cursor (a lagging node would answer with older state and
//! roll a correct row back). The first sighting is stamped with the node's
//! block nonce, read AFTER the value (so the value is from that block or
//! earlier). The write happens on a later sighting once this node's scanner
//! cursor is [`STAMP_MARGIN_BLOCKS`] past that stamp: the scanner has then
//! applied every block the value can come from and still lacks it — it
//! missed that change — so every later seal agrees with the nodes that did
//! not miss it.
//!
//! Cost: at most [`CALLS_PER_TICK`] Klever calls per tick (every call is
//! counted, failed ones too), through the scanner's own request pacing, and
//! only while the scanner is at a freshly polled tip, so block polling
//! always comes first. After a full round the sweep rests for
//! [`ROUND_COOLDOWN`] (not before the first clean round). A wallet the SC
//! says is not registered is not asked about again for
//! [`NEGATIVE_COOLDOWN_SECS`] — anyone can create unregistered `USERS` rows
//! for free, and a peer can propose anything; a lying peer can only cost SC
//! calls (its candidates are capped per round, channel ids beyond the SC's
//! count are dropped, and the peer rotates every round).
//!
//! Failures never count towards anything: a failing item is skipped for
//! this round and revisited in the next. The first round of the local
//! phases without errors and without an unconfirmed observation marks the
//! mirror migrated (sealing waits for that); peer candidates never block it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use libp2p::PeerId;
use tracing::{debug, info, warn};

use crate::chain::sc_views;
use crate::chain::types::DelegationRecord;
use crate::network::snapshot_client::{stream_peer_mirror, ClientHandle};
use crate::storage::anchored_state::{self, AnchoredChannel, AnchoredDelegation, AnchoredUser};
use crate::storage::rocks::Storage;
use crate::storage::schema::{cf, state_keys};

/// How often the sweep runs.
pub const REPAIR_TICK: Duration = Duration::from_secs(30);
/// Rest between full rounds once the mirror is migrated.
const ROUND_COOLDOWN: Duration = Duration::from_secs(30 * 60);
/// Klever calls per tick (each paced by the scanner's request spacing),
/// including the freshness check that opens a working tick.
const CALLS_PER_TICK: usize = 4;
/// Blocks the scanner cursor must be past a sighting's stamp before a write
/// (the stamp comes from `/node/overview`, the value from `/vm/hex` — this
/// covers a little skew between Klever backends).
const STAMP_MARGIN_BLOCKS: u64 = 10;
/// `USERS` rows examined per step (cheap local reads; bounds a flood of
/// unregistered rows that are all in the negative cache).
const MAX_USER_ROWS_PER_STEP: usize = 500;
/// Steps per tick (a channel id, a delegation row, up to
/// [`MAX_USER_ROWS_PER_STEP`] user rows, or one candidate).
const MAX_STEPS_PER_TICK: usize = 64;
/// How long a "not registered" answer is trusted.
const NEGATIVE_COOLDOWN_SECS: u64 = 7 * 86_400;
/// Candidates taken from one peer's mirror per round (input cap).
const MAX_PEER_CANDIDATES: usize = 1_000;
/// Observations awaiting their second sighting.
const MAX_PENDING: usize = 1_000;
/// Deadline for one whole peer-mirror fetch.
const PEER_FETCH_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Memory cap for one peer mirror (an honest mirror is a few MB).
pub const PEER_MIRROR_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Which source the sweep walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Channels,
    Delegations,
    Users,
    Peers,
}

/// Shared pacing with the chain scanner (`KLEVER_REQUEST_MIN_SPACING_MS`).
pub type Throttle = Arc<tokio::sync::Mutex<Option<tokio::time::Instant>>>;

/// Mirror keys the chain scanner wrote since the last repair tick. Any
/// pending sighting on such a key is discarded: "our row is unchanged" must
/// mean no write at all, not merely the same value again (a row that went
/// A → B → A between two sightings would otherwise pass). The scanner and
/// the sweep run in one task, so draining at the start of a tick is exact.
pub type MirrorTouched = Arc<std::sync::Mutex<std::collections::HashSet<Vec<u8>>>>;

/// Consecutive ticks skipped for a lagging Klever node before it is warned
/// about (≈ 10 min).
const LAG_WARN_AFTER_TICKS: u32 = 20;

/// How the sweep reaches other nodes' sealed mirrors.
pub struct PeerSource {
    pub handle: ClientHandle,
    pub network_id: String,
    pub chunk_retries: u32,
}

/// A finished peer fetch: the peer, the height it served, and the keys it
/// holds differently from our mirror.
type PeerFetch = tokio::task::JoinHandle<Result<(PeerId, u64, Vec<Vec<u8>>)>>;

/// An SC value seen once, waiting for its confirming second sighting.
struct Pending {
    value: Vec<u8>,
    /// Our mirror row at the first sighting: the write only happens if it
    /// is unchanged (otherwise the scanner applied something meanwhile and
    /// the comparison starts over).
    ours: Option<Vec<u8>>,
    /// Klever node nonce read after the first sighting; `u64::MAX` until
    /// the end of the tick stamps it (never due before that).
    observed_tip: u64,
}

/// A mirror key, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MirrorKey {
    User(String),
    Channel(u64),
    Delegation(String, String),
}

fn parse_key(key: &[u8]) -> Option<MirrorKey> {
    let (prefix, rest) = key.split_first()?;
    match *prefix {
        anchored_state::USER_PREFIX => Some(MirrorKey::User(String::from_utf8(rest.to_vec()).ok()?)),
        anchored_state::CHANNEL_PREFIX => Some(MirrorKey::Channel(u64::from_be_bytes(rest.try_into().ok()?))),
        anchored_state::DELEGATION_PREFIX => {
            let split = rest.iter().position(|b| *b == 0)?;
            Some(MirrorKey::Delegation(
                String::from_utf8(rest[..split].to_vec()).ok()?,
                String::from_utf8(rest[split + 1..].to_vec()).ok()?,
            ))
        }
        _ => None,
    }
}

/// What to do with a mirror row (`ours`, `None` = missing) the SC reports
/// as `sc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Correction {
    /// Our row equals the SC: nothing to do.
    InSync,
    /// First sighting of this SC value: record it.
    Observe,
    /// Seen before, but the scanner has not passed that sighting's tip yet.
    Wait,
    /// Seen before with the same value, and the scanner has passed the tip
    /// of that sighting while still lacking the value: write it.
    Apply,
}

/// Whether a sighting stamped `observed_tip` is due at `cursor`.
fn passed(cursor: u64, observed_tip: u64) -> bool {
    cursor > observed_tip.saturating_add(STAMP_MARGIN_BLOCKS)
}

fn decide_correction(ours: Option<&[u8]>, sc: &[u8], pending: Option<&Pending>, cursor: u64) -> Correction {
    if ours == Some(sc) {
        return Correction::InSync;
    }
    match pending {
        // Same SC value, and our row unchanged since the first sighting —
        // a value that changed and changed back, or a row the scanner
        // updated meanwhile, starts over instead.
        Some(p) if p.value == sc && p.ours.as_deref() == ours => {
            if passed(cursor, p.observed_tip) {
                Correction::Apply
            } else {
                Correction::Wait
            }
        }
        _ => Correction::Observe,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The repair sweep's state. Owned by the scanner task.
pub struct AnchoredRepair {
    storage: Storage,
    http: reqwest::Client,
    node_url: String,
    contract: String,
    throttle: Throttle,
    spacing: Duration,
    /// Klever calls made so far (every `pace`d call, failed ones too).
    calls: AtomicUsize,
    phase: Phase,
    /// The SC's channel count (bounds peer-proposed channel ids too).
    channel_count: Option<u64>,
    /// Re-read `channel_count` at the start of the next channels pass.
    channel_count_stale: bool,
    /// Whether any item failed during the current round.
    round_had_errors: bool,
    /// Whether the current round recorded an unconfirmed observation (blocks
    /// the first-pass migration: that record is not in the mirror yet).
    round_incomplete: bool,
    /// No new round before this instant.
    next_round_at: Option<tokio::time::Instant>,
    peers: Option<PeerSource>,
    peer_index: usize,
    peer_fetch: Option<PeerFetch>,
    /// Keys proposed by a peer's mirror, still to check against the SC.
    candidates: VecDeque<Vec<u8>>,
    pending: HashMap<Vec<u8>, Pending>,
    /// Keys first observed during the current tick (stamped at its end).
    observed_this_tick: Vec<Vec<u8>>,
    /// Keys the scanner wrote since the last tick (see [`MirrorTouched`]).
    touched: MirrorTouched,
    /// The node's shared device→wallet resolver (for missed revokes).
    identity: crate::storage::identity::IdentityResolver,
    /// Consecutive ticks skipped because the Klever node lagged.
    lag_skips: u32,
    /// While unmigrated, peer candidates alternate with local steps.
    candidate_turn: bool,
}

impl Drop for AnchoredRepair {
    fn drop(&mut self) {
        if let Some(task) = self.peer_fetch.take() {
            task.abort();
        }
    }
}

impl AnchoredRepair {
    pub fn new(
        storage: Storage,
        http: reqwest::Client,
        node_url: String,
        contract: String,
        throttle: Throttle,
        spacing: Duration,
        peers: Option<PeerSource>,
        touched: MirrorTouched,
        identity: crate::storage::identity::IdentityResolver,
    ) -> Self {
        Self {
            storage,
            http,
            node_url,
            contract,
            throttle,
            spacing,
            calls: AtomicUsize::new(0),
            phase: Phase::Channels,
            channel_count: None,
            channel_count_stale: true,
            round_had_errors: false,
            round_incomplete: false,
            next_round_at: None,
            peers,
            peer_index: 0,
            peer_fetch: None,
            candidates: VecDeque::new(),
            pending: HashMap::new(),
            observed_this_tick: Vec::new(),
            touched,
            identity,
            lag_skips: 0,
            candidate_turn: false,
        }
    }

    /// Wait for the shared request spacing, and count the call.
    async fn pace(&self) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mut last = self.throttle.lock().await;
        if let Some(prev) = *last {
            let next = prev + self.spacing;
            let now = tokio::time::Instant::now();
            if next > now {
                tokio::time::sleep(next - now).await;
            }
        }
        *last = Some(tokio::time::Instant::now());
    }

    fn cursor(&self, key: &[u8]) -> Vec<u8> {
        self.storage.get_cf(cf::NODE_STATE, key).ok().flatten().unwrap_or_default()
    }

    fn set_cursor(&self, key: &[u8], value: &[u8]) {
        if let Err(e) = self.storage.put_cf(cf::NODE_STATE, key, value) {
            warn!(error = %e, "anchored repair: cursor write failed");
        }
    }

    fn migrated(&self) -> bool {
        self.storage.anchored_state_migrated().unwrap_or(true)
    }

    /// Note a failed item: it is skipped this round, and the round cannot
    /// complete the migration.
    fn failed(&mut self, what: &str, e: anyhow::Error) {
        self.round_had_errors = true;
        warn!(error = %e, "anchored repair: {what} failed — skipped this round");
    }

    fn end_phase(&mut self) {
        self.phase = match self.phase {
            Phase::Channels => Phase::Delegations,
            Phase::Delegations => Phase::Users,
            Phase::Users => {
                self.finish_local_round();
                Phase::Peers
            }
            Phase::Peers => {
                // Rest between rounds — but not while the mirror is still
                // being filled.
                if self.migrated() {
                    self.next_round_at = Some(tokio::time::Instant::now() + ROUND_COOLDOWN);
                }
                Phase::Channels
            }
        };
    }

    /// End of the local phases: decide the first-pass migration.
    fn finish_local_round(&mut self) {
        if !self.migrated() {
            if !self.round_had_errors && !self.round_incomplete {
                match self.storage.set_anchored_state_migrated() {
                    Ok(()) => info!("Anchored chain mirror filled from the smart contract — sealing anchor checkpoints from now on"),
                    Err(e) => warn!(error = %e, "anchored repair: could not mark the mirror migrated"),
                }
            } else {
                info!(
                    errors = self.round_had_errors,
                    awaiting_confirmation = self.round_incomplete,
                    "Anchored repair round not clean yet — no anchor checkpoints are sealed until one is"
                );
            }
        }
        self.round_had_errors = false;
        self.round_incomplete = false;
    }

    fn has_work(&self, cursor: u64) -> bool {
        self.due(cursor).is_some()
            || !self.candidates.is_empty()
            || self.peer_fetch.as_ref().is_some_and(|t| t.is_finished())
            || !self.next_round_at.is_some_and(|t| tokio::time::Instant::now() < t)
    }

    /// One tick: spend up to [`CALLS_PER_TICK`] Klever calls. Due
    /// confirmations and peer candidates go first, then the round's phases
    /// (unless resting). `cursor` is the scanner's chain cursor.
    ///
    /// A working tick first checks that the Klever node has reached our
    /// cursor: a lagging node would answer with state OLDER than what the
    /// scanner already applied, and a write from it would roll a correct
    /// row back.
    pub async fn tick(&mut self, cursor: u64) {
        // The scanner wrote these rows since the last tick: their pending
        // sightings no longer describe "our row unchanged".
        let touched: Vec<Vec<u8>> = match self.touched.lock() {
            Ok(mut set) => set.drain().collect(),
            Err(poisoned) => poisoned.into_inner().drain().collect(),
        };
        for key in touched {
            self.pending.remove(&key);
        }
        if !self.has_work(cursor) {
            return;
        }
        let start = self.calls.load(Ordering::Relaxed);
        self.pace().await;
        match sc_views::get_node_nonce(&self.http, &self.node_url).await {
            Ok(nonce) if nonce >= cursor => self.lag_skips = 0,
            Ok(nonce) => {
                self.lag_skips = self.lag_skips.saturating_add(1);
                if self.lag_skips % LAG_WARN_AFTER_TICKS == 0 {
                    warn!(
                        nonce,
                        cursor,
                        "anchored repair: `[klever] node_url` keeps lagging behind the chain scanner — repair (and, before the first pass, sealing and anchoring) is paused"
                    );
                } else {
                    debug!(nonce, cursor, "anchored repair: the Klever node is behind our cursor — skipping this tick");
                }
                return;
            }
            Err(e) => {
                warn!(error = %e, "anchored repair: cannot read the Klever node nonce (`[klever] node_url` must serve /node/overview) — repair paused");
                return;
            }
        }
        let mut steps = 0usize;
        while self.calls.load(Ordering::Relaxed) - start < CALLS_PER_TICK && steps < MAX_STEPS_PER_TICK {
            steps += 1;
            if let Some(key) = self.due(cursor) {
                if let Err(e) = self.check_key(&key, cursor, false).await {
                    debug!(error = %e, "anchored repair: confirmation failed");
                }
                continue;
            }
            // Before the first pass completes, candidates alternate with
            // local steps: a peer must not be able to delay the migration.
            self.candidate_turn = !self.candidate_turn;
            let candidates_first = self.candidate_turn || self.migrated();
            if candidates_first || self.next_round_at.is_some_and(|t| tokio::time::Instant::now() < t) {
                if let Some(key) = self.candidates.pop_front() {
                    if let Err(e) = self.check_key(&key, cursor, false).await {
                        debug!(error = %e, "anchored repair: peer candidate check failed");
                    }
                    continue;
                }
            }
            if self.next_round_at.is_some_and(|t| tokio::time::Instant::now() < t) {
                break;
            }
            let yield_tick = match self.phase {
                Phase::Channels => {
                    self.step_channel(cursor).await;
                    false
                }
                Phase::Delegations => {
                    self.step_delegation(cursor).await;
                    false
                }
                Phase::Users => {
                    self.step_users(cursor).await;
                    false
                }
                Phase::Peers => self.step_peers().await,
            };
            if yield_tick {
                break;
            }
        }
        self.stamp_observations().await;
    }

    /// A pending observation whose stamp the scanner has passed.
    fn due(&self, cursor: u64) -> Option<Vec<u8>> {
        self.pending.iter().find(|(_, p)| passed(cursor, p.observed_tip)).map(|(k, _)| k.clone())
    }

    /// Stamp this tick's first sightings with the Klever node's nonce, read
    /// now — after every value they saw. Without a nonce they are dropped
    /// (re-observed later), never left unstamped.
    async fn stamp_observations(&mut self) {
        if self.observed_this_tick.is_empty() {
            return;
        }
        let keys = std::mem::take(&mut self.observed_this_tick);
        self.pace().await;
        match sc_views::get_node_nonce(&self.http, &self.node_url).await {
            Ok(nonce) => {
                for k in keys {
                    if let Some(p) = self.pending.get_mut(&k) {
                        p.observed_tip = nonce;
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "anchored repair: could not read the Klever node nonce — dropping this tick's observations");
                for k in keys {
                    self.pending.remove(&k);
                }
            }
        }
    }

    /// Check one mirror key against the SC and act on [`decide_correction`].
    /// `counts_for_round`: an unconfirmed observation from the local phases
    /// keeps the first-pass migration open; one from a peer candidate or a
    /// due re-check does not (a peer must never be able to stall it).
    async fn check_key(&mut self, key: &[u8], cursor: u64, counts_for_round: bool) -> Result<()> {
        let Some(parsed) = parse_key(key) else {
            self.pending.remove(key);
            return Ok(());
        };
        match &parsed {
            // A channel id the SC never assigned (a peer can propose any);
            // with the count unknown, nothing is checked.
            MirrorKey::Channel(id) if *id == 0 || self.channel_count.is_none_or(|c| *id > c) => {
                self.pending.remove(key);
                return Ok(());
            }
            MirrorKey::User(address) | MirrorKey::Delegation(address, _) => {
                if crate::crypto::address_to_verifying_key(address).is_err() {
                    self.pending.remove(key);
                    return Ok(());
                }
                if let MirrorKey::User(address) = &parsed {
                    let negative = self.storage.anchored_repair_negative_at(address);
                    if negative.as_ref().map_or(true, |n| {
                        n.is_some_and(|at| now_secs().saturating_sub(at) < NEGATIVE_COOLDOWN_SECS)
                    }) {
                        // Never leave a pending entry behind on an early
                        // return (it would be due again every step).
                        self.pending.remove(key);
                        return negative.map(|_| ());
                    }
                }
            }
            MirrorKey::Channel(_) => {}
        }
        let sc = match self.sc_record(&parsed).await {
            Ok(Some(v)) => v,
            Ok(None) => {
                // Not on-chain. A registration cannot be undone, so there is
                // nothing to write; remember a non-registered wallet.
                self.pending.remove(key);
                if let MirrorKey::User(address) = &parsed {
                    self.storage.set_anchored_repair_negative(address, now_secs())?;
                }
                return Ok(());
            }
            Err(e) => {
                // Dropped, not retried every tick; proposed again later.
                self.pending.remove(key);
                return Err(e);
            }
        };
        let ours = match self.storage.get_cf(cf::ANCHORED_STATE, key) {
            Ok(v) => v,
            Err(e) => {
                self.pending.remove(key);
                return Err(e);
            }
        };
        match decide_correction(ours.as_deref(), &sc, self.pending.get(key), cursor) {
            Correction::InSync => {
                self.pending.remove(key);
            }
            Correction::Apply => {
                // A missed revoke is applied to authentication FIRST: if
                // that fails, the mirror row stays unwritten, so the next
                // round sees the difference and retries.
                if let MirrorKey::Delegation(user, device_key) = &parsed {
                    if let Err(e) = self.apply_missed_revoke(user, device_key, &sc) {
                        self.pending.remove(key);
                        return Err(e);
                    }
                }
                self.storage.put_cf(cf::ANCHORED_STATE, key, &sc)?;
                info!(
                    key = %hex::encode(key),
                    inserted = ours.is_none(),
                    "anchored repair: wrote a record the scanner missed (SC-confirmed twice)"
                );
                self.pending.remove(key);
            }
            Correction::Wait => {
                if counts_for_round && !self.migrated() {
                    self.round_incomplete = true;
                }
            }
            Correction::Observe => {
                if counts_for_round && !self.migrated() {
                    self.round_incomplete = true;
                }
                if self.pending.len() < MAX_PENDING || self.pending.contains_key(key) {
                    self.pending.insert(key.to_vec(), Pending { value: sc, ours, observed_tip: u64::MAX });
                    self.observed_this_tick.push(key.to_vec());
                }
            }
        }
        Ok(())
    }

    /// A confirmed delegation record the scanner missed may carry a revoke:
    /// apply it like the scanner's revoke does — remove the device→wallet
    /// mapping (what device authentication resolves through, shared cache
    /// included) with a revocation tombstone, and deactivate the node's own
    /// `DELEGATIONS` row — not only the mirror.
    fn apply_missed_revoke(&self, user: &str, device_key: &str, confirmed: &[u8]) -> Result<()> {
        let Ok(record) = serde_json::from_slice::<AnchoredDelegation>(confirmed) else { return Ok(()) };
        if record.revoked_at == 0 {
            return Ok(());
        }
        if let Some(device_address) = crate::storage::identity::device_address_from_hex_key(device_key) {
            if self.identity.revoke_device_from_chain(&device_address, user, record.revoked_at.saturating_mul(1000))? {
                warn!(user, device = %device_address, "anchored repair: applied an on-chain revoke the scanner missed — device mapping removed");
            }
        }
        let key = crate::storage::schema::encode_delegation_key(user, device_key);
        let Some(row) = self.storage.get_cf(cf::DELEGATIONS, &key)? else { return Ok(()) };
        let Ok(mut d) = serde_json::from_slice::<DelegationRecord>(&row) else { return Ok(()) };
        if d.active {
            d.active = false;
            self.storage.put_cf(cf::DELEGATIONS, &key, &serde_json::to_vec(&d)?)?;
        }
        Ok(())
    }

    /// The SC's current canonical record for `key`, or `None` if the SC has
    /// none.
    async fn sc_record(&self, key: &MirrorKey) -> Result<Option<Vec<u8>>> {
        Ok(match key {
            MirrorKey::User(address) => {
                self.pace().await;
                sc_views::get_user_pub_key(&self.http, &self.node_url, &self.contract, address)
                    .await?
                    .map(|public_key| anchored_state::encode(&AnchoredUser { address: address.clone(), public_key }))
                    .transpose()?
            }
            MirrorKey::Channel(id) => {
                self.pace().await;
                let slug = sc_views::get_channel_slug(&self.http, &self.node_url, &self.contract, *id).await?;
                let Some(slug) = slug else { return Ok(None) };
                self.pace().await;
                let creator = sc_views::get_channel_creator(&self.http, &self.node_url, &self.contract, *id).await?;
                let Some(creator) = creator else { return Ok(None) };
                Some(anchored_state::encode(&AnchoredChannel { channel_id: *id, creator, slug })?)
            }
            MirrorKey::Delegation(user, device_key) => {
                self.pace().await;
                sc_views::get_delegation(&self.http, &self.node_url, &self.contract, user, device_key)
                    .await?
                    .map(|d| {
                        anchored_state::encode(&AnchoredDelegation {
                            created_at: d.created_at,
                            device_key: device_key.clone(),
                            expires_at: d.expires_at,
                            permissions: d.permissions,
                            revoked_at: d.revoked_at,
                            user: user.clone(),
                        })
                    })
                    .transpose()?
            }
        })
    }

    /// Check the next channel id the mirror lacks.
    async fn step_channel(&mut self, cursor: u64) {
        let count = match self.channel_count {
            Some(c) if !self.channel_count_stale => c,
            _ => {
                self.pace().await;
                match sc_views::get_stats(&self.http, &self.node_url, &self.contract).await {
                    Ok((_, c, _)) => {
                        self.channel_count = Some(c);
                        self.channel_count_stale = false;
                        c
                    }
                    Err(e) => {
                        self.failed("getStats", e);
                        self.end_phase();
                        return;
                    }
                }
            }
        };
        let raw = self.cursor(state_keys::ANCHORED_REPAIR_CHANNEL_CURSOR);
        let id = <[u8; 8]>::try_from(raw.as_slice()).map(u64::from_be_bytes).unwrap_or(0) + 1;
        if id > count {
            self.set_cursor(state_keys::ANCHORED_REPAIR_CHANNEL_CURSOR, &0u64.to_be_bytes());
            // The count stays cached (it bounds peer candidates) until the
            // next channels pass refreshes it.
            self.channel_count_stale = true;
            self.end_phase();
            return;
        }
        let key = anchored_state::channel_key(id);
        match self.storage.anchored_contains(&key) {
            Ok(true) => {}
            Ok(false) => {
                if let Err(e) = self.check_key(&key, cursor, true).await {
                    self.failed(&format!("channel {id}"), e);
                }
            }
            Err(e) => self.failed("reading the mirror", e),
        }
        self.set_cursor(state_keys::ANCHORED_REPAIR_CHANNEL_CURSOR, &id.to_be_bytes());
    }

    /// Check the next `DELEGATIONS` row — missing AND existing mirror rows:
    /// a missed revoke must not survive in proofs.
    async fn step_delegation(&mut self, cursor: u64) {
        let pos = self.cursor(state_keys::ANCHORED_REPAIR_DELEGATION_CURSOR);
        let next = if pos.is_empty() {
            self.storage.prefix_iter_cf(cf::DELEGATIONS, &[], 1)
        } else {
            self.storage.prefix_iter_cf_after(cf::DELEGATIONS, &pos, &[], 1)
        };
        let row = match next {
            Ok(mut rows) => rows.pop(),
            Err(e) => {
                self.failed("reading DELEGATIONS", e);
                None
            }
        };
        let Some((row_key, value)) = row else {
            self.set_cursor(state_keys::ANCHORED_REPAIR_DELEGATION_CURSOR, &[]);
            self.end_phase();
            return;
        };
        // Scanner-owned rows; one that does not decode is skipped.
        if let Ok(d) = serde_json::from_slice::<DelegationRecord>(&value) {
            let key = anchored_state::delegation_key(&d.user_address, &d.device_pub_key);
            if let Err(e) = self.check_key(&key, cursor, true).await {
                self.failed("delegation", e);
            }
        }
        self.set_cursor(state_keys::ANCHORED_REPAIR_DELEGATION_CURSOR, &row_key);
    }

    /// Walk `USERS` rows to the next wallet the mirror lacks and check it.
    /// The cursor is written once per step.
    async fn step_users(&mut self, cursor: u64) {
        let migrated = self.migrated();
        let now = now_secs();
        let pos = self.cursor(state_keys::ANCHORED_REPAIR_USER_CURSOR);
        let rows = if pos.is_empty() {
            self.storage.prefix_iter_cf(cf::USERS, &[], MAX_USER_ROWS_PER_STEP)
        } else {
            self.storage.prefix_iter_cf_after(cf::USERS, &pos, &[], MAX_USER_ROWS_PER_STEP)
        };
        let rows = match rows {
            Ok(r) => r,
            Err(e) => {
                self.failed("reading USERS", e);
                self.end_phase();
                return;
            }
        };
        if rows.is_empty() {
            self.set_cursor(state_keys::ANCHORED_REPAIR_USER_CURSOR, &[]);
            self.end_phase();
            return;
        }
        let mut last_key = Vec::new();
        for (row_key, value) in rows {
            last_key = row_key.clone();
            let Ok(address) = std::str::from_utf8(&row_key) else { continue };
            let key = anchored_state::user_key(address);
            match self.storage.anchored_contains(&key) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => {
                    self.failed("reading the mirror", e);
                    continue;
                }
            }
            // Until the first clean round, only wallets the scanner itself
            // recorded as registered: a flood of unregistered rows must not
            // delay the migration.
            if !migrated {
                let registered_at = serde_json::from_slice::<serde_json::Value>(&value)
                    .ok()
                    .and_then(|v| v.get("registered_at").and_then(|r| r.as_u64()))
                    .unwrap_or(0);
                if registered_at == 0 {
                    continue;
                }
            }
            if self
                .storage
                .anchored_repair_negative_at(address)
                .ok()
                .flatten()
                .is_some_and(|at| now.saturating_sub(at) < NEGATIVE_COOLDOWN_SECS)
            {
                continue;
            }
            if let Err(e) = self.check_key(&key, cursor, true).await {
                self.failed("user", e);
            }
            break;
        }
        self.set_cursor(state_keys::ANCHORED_REPAIR_USER_CURSOR, &last_key);
    }

    /// Fetch one connected peer's sealed mirror in the background (the
    /// scanner never waits on the network; the whole fetch has a deadline)
    /// and queue every row it holds differently from ours. Returns whether
    /// to yield the rest of the tick.
    async fn step_peers(&mut self) -> bool {
        let Some(peers) = self.peers.as_ref() else {
            self.end_phase();
            return false;
        };
        match self.peer_fetch.take() {
            None => {
                let handle = peers.handle.clone();
                let network_id = peers.network_id.clone();
                let retries = peers.chunk_retries;
                let storage = self.storage.clone();
                let index = self.peer_index;
                self.peer_index = self.peer_index.wrapping_add(1);
                self.peer_fetch = Some(tokio::spawn(async move {
                    tokio::time::timeout(PEER_FETCH_TIMEOUT, async move {
                        let connected = handle.connected_peers().await.map_err(|e| anyhow::anyhow!("{e}"))?;
                        let Some(peer) = connected.get(index % connected.len().max(1)).copied() else {
                            anyhow::bail!("no connected peers");
                        };
                        // Diff while streaming: only the differing keys are
                        // kept (≤ MAX_PEER_CANDIDATES), never the rows.
                        let mut differing = Vec::new();
                        let mut read_error = None;
                        let height = stream_peer_mirror(&handle, peer, &network_id, PEER_MIRROR_MAX_BYTES, retries, |k, v| {
                            match storage.get_cf(cf::ANCHORED_STATE, k) {
                                Ok(Some(ours)) if ours == v => {}
                                Ok(_) => differing.push(k.to_vec()),
                                Err(e) => {
                                    read_error = Some(e);
                                    return false;
                                }
                            }
                            differing.len() < MAX_PEER_CANDIDATES
                        })
                        .await?;
                        if let Some(e) = read_error {
                            return Err(e);
                        }
                        Ok((peer, height, differing))
                    })
                    .await
                    .map_err(|_| anyhow::anyhow!("peer mirror fetch timed out"))?
                }));
                true
            }
            Some(task) if !task.is_finished() => {
                self.peer_fetch = Some(task);
                true
            }
            Some(task) => {
                // Finished: awaiting it returns at once.
                match task.await {
                    Ok(Ok((peer, height, keys))) => {
                        if !keys.is_empty() {
                            info!(%peer, height, queued = keys.len(), "anchored repair: peer mirror differs — checking those records against the SC");
                        }
                        self.candidates.extend(keys);
                    }
                    Ok(Err(e)) => debug!(error = %e, "anchored repair: peer mirror fetch failed"),
                    Err(e) => debug!(error = %e, "anchored repair: peer mirror task failed"),
                }
                self.end_phase();
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_write_needs_two_sightings_across_the_scanner_passing_the_first_tip() {
        let p = |value: &[u8], ours: Option<&[u8]>, observed_tip| Pending {
            value: value.to_vec(),
            ours: ours.map(<[u8]>::to_vec),
            observed_tip,
        };
        let due = 100 + STAMP_MARGIN_BLOCKS + 1;
        // In sync: nothing to do, whatever is pending.
        assert_eq!(decide_correction(Some(b"v1"), b"v1", None, 10), Correction::InSync);
        assert_eq!(decide_correction(Some(b"v1"), b"v1", Some(&p(b"v2", Some(b"v1"), 5)), 10), Correction::InSync);
        // First sighting of a differing value, or of a missing record.
        assert_eq!(decide_correction(Some(b"v1"), b"v2", None, 10), Correction::Observe);
        assert_eq!(decide_correction(None, b"v2", None, 10), Correction::Observe);
        // Unstamped (this tick), or the scanner is not past stamp + margin:
        // the change may be in a block it has yet to apply.
        assert_eq!(decide_correction(None, b"v2", Some(&p(b"v2", None, u64::MAX)), u64::MAX - 1), Correction::Wait);
        assert_eq!(decide_correction(Some(b"v1"), b"v2", Some(&p(b"v2", Some(b"v1"), 100)), due - 1), Correction::Wait);
        // Past it, our row unchanged and still lacking the value: the
        // scanner missed the change.
        assert_eq!(decide_correction(Some(b"v1"), b"v2", Some(&p(b"v2", Some(b"v1"), 100)), due), Correction::Apply);
        assert_eq!(decide_correction(None, b"v2", Some(&p(b"v2", None, 100)), due), Correction::Apply);
        // The SC moved on to another value: start over.
        assert_eq!(decide_correction(Some(b"v1"), b"v3", Some(&p(b"v2", Some(b"v1"), 100)), due), Correction::Observe);
        // Round-3 W-B: v → w (scanner applied w) → v again. Our row changed
        // since the first sighting, so the old value is NOT written back.
        assert_eq!(decide_correction(Some(b"w"), b"v", Some(&p(b"v", Some(b"u"), 100)), due), Correction::Observe);
    }

    // Round-4 W1: a scanner write between two sightings discards the
    // pending one, even if the row ends up at its old value again.
    #[tokio::test]
    async fn a_scanner_write_discards_the_pending_sighting() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let touched: MirrorTouched = Default::default();
        let mut repair = AnchoredRepair::new(
            storage,
            reqwest::Client::new(),
            "http://127.0.0.1:9".into(),
            "klv1contract".into(),
            Arc::new(tokio::sync::Mutex::new(None)),
            Duration::ZERO,
            None,
            touched.clone(),
            crate::storage::identity::IdentityResolver::new(Storage::open(dir.path().join("id").as_path()).unwrap()),
        );
        let key = anchored_state::channel_key(7);
        let other = anchored_state::channel_key(8);
        for k in [&key, &other] {
            repair.pending.insert(k.clone(), Pending { value: b"B".to_vec(), ours: Some(b"A".to_vec()), observed_tip: 100 });
        }
        touched.lock().unwrap().insert(key.clone());
        repair.tick(0).await;
        assert!(!repair.pending.contains_key(&key), "touched key discarded");
        assert!(repair.pending.contains_key(&other), "untouched key kept");
        assert!(touched.lock().unwrap().is_empty(), "set drained");
    }

    #[test]
    fn mirror_keys_parse_back() {
        assert_eq!(parse_key(&anchored_state::user_key("klv1a")), Some(MirrorKey::User("klv1a".into())));
        assert_eq!(parse_key(&anchored_state::channel_key(20)), Some(MirrorKey::Channel(20)));
        assert_eq!(
            parse_key(&anchored_state::delegation_key("klv1a", "dd")),
            Some(MirrorKey::Delegation("klv1a".into(), "dd".into()))
        );
        assert_eq!(parse_key(b"c\x00\x01"), None);
        assert_eq!(parse_key(b"dklv1a"), None);
        assert_eq!(parse_key(b"x"), None);
    }
}
