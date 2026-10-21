//! Rolling-window responder budgets and the requester-side attempt throttle
//! for the channel-history backfill protocols (l2-node 0.141.0).
//!
//! Pure, clock-injected building blocks — every function that needs the
//! time takes `now: Instant` as a parameter, and the throttle takes its
//! jitter as a parameter, so the tests can drive days of simulated time
//! deterministically. Nothing here touches storage, the swarm or the wall
//! clock.
//!
//! # Responder side: GCRA budgets
//!
//! Before 0.141.0 the private-channel-sync and reconcile responders kept a
//! LIFETIME counter of work served per peer (resp. per `(peer, channel)`)
//! that never refilled until the process restarted. A requester that
//! re-walked an already-in-sync channel every 30 s burned through it in
//! hours and was then answered `server_capped` until the responder
//! restarted. The private limiter also evicted its oldest entry FIFO past
//! 100k peers, so a Sybil cycling 100k identities got its budget back; the
//! reconcile map was never pruned at all and its key includes a
//! requester-chosen `channel_id`.
//!
//! [`Gcra`] (generic cell rate algorithm) replaces the counter with a
//! rolling window: each key holds one "theoretical arrival time" (`tat`).
//! A request is admitted while the key's debt (`tat - now`) is below the
//! burst tolerance; serving it pushes `tat` forward by `units × per_unit`.
//! Debt drains in real time, so a key regains `refill_per_hour` units per
//! hour, up to `burst`.
//!
//! [`BudgetMap`] holds the per-key `tat`s with a hard key cap. It prunes
//! ONLY entries whose bucket is full again (`tat <= now`) — such an entry
//! carries no information, so dropping it never grants a free refill — and
//! when it is still full after pruning it REFUSES new keys (fail closed);
//! existing keys are unaffected. There is no FIFO eviction any more.
//!
//! # Requester side: attempt throttle
//!
//! [`AttemptThrottle`] stops the requester from re-walking a channel every
//! 30 s sweep tick. It is in memory only (no entry == due, which is exactly
//! the pre-0.141.0 behaviour, so a restart costs one attempt per key and a
//! downgrade is safe). A key is stamped when requests are actually SENT;
//! each dispatch counts as a failure until an outcome says otherwise:
//!
//! * dispatch: `failures += 1`, next attempt after
//!   `min(30 s × 2^(failures-1), retry_backoff_max) ± 20 %`;
//! * COMPLETE: entry removed (the persisted completion marker and
//!   `channel_catchup_interval_hours` take over);
//! * accepted-but-incomplete (a session admitted new content but stopped
//!   early): `failures = 0`, next attempt after 30 s;
//! * IN_SYNC (a verified "nothing new" result — a THROTTLE STATE ONLY,
//!   never a completion): `failures = 0`, next attempt after
//!   `in_sync_recheck ± 20 %`;
//! * anything else keeps the backoff set at dispatch.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Nanoseconds in one hour.
const HOUR_NS: u128 = 3_600 * 1_000_000_000;

/// Convert a nanosecond count to a `Duration`, saturating instead of
/// overflowing.
fn duration_from_ns(ns: u128) -> Duration {
    let secs = ns / 1_000_000_000;
    let sub = (ns % 1_000_000_000) as u32;
    Duration::new(u64::try_from(secs).unwrap_or(u64::MAX), sub)
}

/// Why a responder refused a request (answered `server_capped`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A per-peer / per-pair concurrency slot was not free.
    Concurrency,
    /// The key's rolling budget is exhausted (debt >= burst tolerance).
    OverBudget,
    /// The key is new and the budget map is at its hard key cap.
    MapFull,
}

/// A rolling-window budget: `burst` units, refilled at `refill_per_hour`
/// units per hour. Stateless — the per-key state is a single `Instant`
/// (`tat`, held by [`BudgetMap`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gcra {
    /// Time one unit takes to refill (`1 h / refill_per_hour`), in ns.
    per_unit_ns: u128,
    /// Burst tolerance (`burst × per_unit`).
    tolerance: Duration,
}

impl Gcra {
    /// Budget of `burst` units refilling at `refill_per_hour`. Both are
    /// clamped to at least 1 (config validation rejects 0; the clamp only
    /// keeps a hand-built value from dividing by zero).
    pub fn new(burst: u64, refill_per_hour: u64) -> Self {
        let burst = burst.max(1) as u128;
        let refill = refill_per_hour.max(1) as u128;
        let per_unit_ns = (HOUR_NS / refill).max(1);
        Self {
            per_unit_ns,
            tolerance: duration_from_ns(per_unit_ns.saturating_mul(burst)),
        }
    }

    /// Admit a request for a key whose state is `tat` (`None` = a fresh,
    /// full bucket): allowed while at least one WHOLE unit of budget
    /// remains, i.e. the key's debt `max(tat, now) - now` plus one unit's
    /// refill time is within the burst tolerance. Refusals are never
    /// charged.
    pub fn admit(&self, tat: Option<Instant>, now: Instant) -> bool {
        let per_unit = duration_from_ns(self.per_unit_ns);
        tat.is_none_or(|t| t.saturating_duration_since(now).saturating_add(per_unit) <= self.tolerance)
    }

    /// The key's new `tat` after serving `units`:
    /// `max(tat, now) + units × per_unit`, clamped to at most
    /// `now + 2 × tolerance` (bounded debt) and never panicking on
    /// overflow. Charging after the build (as the responders do) means two
    /// requests admitted together can push a key into debt — the debt is
    /// simply paid off before it is admitted again.
    pub fn charge(&self, tat: Option<Instant>, units: u64, now: Instant) -> Instant {
        let base = tat.map_or(now, |t| t.max(now));
        let max_debt = self.tolerance.saturating_mul(2);
        let add_ns = self.per_unit_ns.saturating_mul(units as u128).min(max_debt.as_nanos());
        let add = duration_from_ns(add_ns);
        let limit = now.checked_add(max_debt);
        let new = base.checked_add(add).or(limit).unwrap_or(base);
        match limit {
            Some(l) => new.min(l),
            None => new,
        }
    }
}

/// Minimum spacing between on-demand prunes of a full [`BudgetMap`].
pub const DEMAND_PRUNE_INTERVAL: Duration = Duration::from_secs(1);

/// Per-key GCRA state with a hard key cap (see the module doc).
#[derive(Debug)]
pub struct BudgetMap<K> {
    tats: HashMap<K, Instant>,
    cap: usize,
    /// When the last on-demand prune (triggered by a full map) ran.
    last_demand_prune: Option<Instant>,
}

impl<K: Eq + Hash> BudgetMap<K> {
    /// Empty map refusing NEW keys once it holds `cap` keys.
    pub fn new(cap: usize) -> Self {
        Self { tats: HashMap::new(), cap, last_demand_prune: None }
    }

    /// Admit a request for `key` under `gcra`. An existing key is admitted
    /// by its own budget only; a NEW key is admitted only while the map
    /// has room (fail closed — `Refusal::MapFull`). Does not insert: the
    /// key enters the map when it is charged.
    ///
    /// A full map first prunes refilled buckets on demand (at most once per
    /// [`DEMAND_PRUNE_INTERVAL`]): otherwise a flood of one-unit requests
    /// for fresh keys could keep the map full between the periodic prunes
    /// and lock every honest newcomer out. Entries in debt are never pruned.
    pub fn admit(&mut self, key: &K, gcra: &Gcra, now: Instant) -> Result<(), Refusal> {
        if !self.tats.contains_key(key) && self.tats.len() >= self.cap {
            let due = self
                .last_demand_prune
                .is_none_or(|t| now.saturating_duration_since(t) >= DEMAND_PRUNE_INTERVAL);
            if due {
                self.last_demand_prune = Some(now);
                self.prune(now);
            }
        }
        match self.tats.get(key) {
            Some(&tat) => {
                if gcra.admit(Some(tat), now) {
                    Ok(())
                } else {
                    Err(Refusal::OverBudget)
                }
            }
            None if self.tats.len() >= self.cap => Err(Refusal::MapFull),
            None => Ok(()),
        }
    }

    /// Charge `units` to `key` (after the request was served). Always
    /// records the charge, even past the cap: the key was admitted, and
    /// dropping its charge would be a free refill. The overshoot is bounded
    /// by the number of requests admitted but not yet charged (the
    /// responders' concurrency and build-slot limits).
    pub fn charge(&mut self, key: K, units: u64, gcra: &Gcra, now: Instant) {
        let tat = self.tats.get(&key).copied();
        self.tats.insert(key, gcra.charge(tat, units, now));
    }

    /// Drop every entry whose bucket is full again (`tat <= now`). An entry
    /// still in debt is NEVER dropped — that would hand its owner a free
    /// refill (the pre-0.141.0 FIFO-eviction bypass). Returns how many
    /// entries were removed.
    pub fn prune(&mut self, now: Instant) -> usize {
        let before = self.tats.len();
        self.tats.retain(|_, tat| *tat > now);
        before - self.tats.len()
    }

    /// Number of tracked keys (tests).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.tats.len()
    }

    /// `true` when no key is tracked (tests).
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.tats.is_empty()
    }

    /// The key's current `tat` (tests).
    #[cfg(test)]
    pub fn tat(&self, key: &K) -> Option<Instant> {
        self.tats.get(key).copied()
    }
}

// --- Requester-side attempt throttle ---

/// Base retry interval: the first backoff step, and the recheck after an
/// accepted-but-incomplete session. Equal to the sweep tick.
pub const BASE_RETRY: Duration = Duration::from_secs(30);

/// ± fraction applied to the dispatch backoff and the in-sync recheck so
/// keys stamped on the same tick spread out instead of firing together.
pub const JITTER_FRACTION: f64 = 0.2;

/// A private-channel federate call that carries a fresh wallet claim may
/// bypass the throttle, but only if the key's last dispatch is at least
/// this old — so a client re-federating in a loop cannot turn the bypass
/// into a request flood.
pub const FEDERATE_BYPASS_FLOOR: Duration = Duration::from_secs(60);

/// Hard cap on tracked throttle keys per protocol.
pub const MAX_THROTTLE_KEYS: usize = 100_000;

/// Scale `d` by `1 + JITTER_FRACTION × jitter`, `jitter` in `[-1, 1]`
/// (clamped; NaN counts as 0). Callers pass a uniform random value in
/// production and a fixed one in tests.
pub fn jittered(d: Duration, jitter: f64) -> Duration {
    let j = if jitter.is_nan() { 0.0 } else { jitter.clamp(-1.0, 1.0) };
    Duration::try_from_secs_f64(d.as_secs_f64() * (1.0 + JITTER_FRACTION * j)).unwrap_or(d)
}

/// `now + d`, never panicking: an unrepresentable instant (only reachable
/// with absurd, unvalidated durations) is capped at about a year out.
fn later(now: Instant, d: Duration) -> Instant {
    now.checked_add(d)
        .or_else(|| now.checked_add(Duration::from_secs(365 * 24 * 3_600)))
        .unwrap_or(now)
}

/// A uniform jitter value in `[-1, 1]` for production callers.
pub fn random_jitter() -> f64 {
    use rand::Rng;
    rand::thread_rng().gen_range(-1.0..=1.0)
}

/// Dispatch backoff after the `failures`-th consecutive unsuccessful
/// attempt: `min(BASE_RETRY × 2^(failures-1), max)`, before jitter.
pub fn backoff(failures: u32, max: Duration) -> Duration {
    let shift = failures.saturating_sub(1).min(30);
    let secs = BASE_RETRY.as_secs().saturating_mul(1u64 << shift);
    Duration::from_secs(secs).min(max)
}

/// Throttle state of one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThrottleEntry {
    /// Earliest time the key may be attempted again.
    pub next_due: Instant,
    /// Consecutive dispatches without a success/in-sync outcome.
    pub failures: u32,
    /// When requests were last actually sent for this key (`None` if the
    /// entry was created by an outcome after the dispatch entry was
    /// evicted).
    pub last_dispatch: Option<Instant>,
}

/// In-memory per-key attempt throttle (see the module doc).
#[derive(Debug)]
pub struct AttemptThrottle<K> {
    entries: HashMap<K, ThrottleEntry>,
    cap: usize,
    backoff_max: Duration,
    in_sync_recheck: Duration,
}

impl<K: Eq + Hash + Clone> AttemptThrottle<K> {
    /// Empty throttle with the given caps and intervals.
    pub fn new(cap: usize, backoff_max: Duration, in_sync_recheck: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            cap: cap.max(1),
            backoff_max,
            in_sync_recheck,
        }
    }

    /// `true` when `key` may be attempted now (no entry == due).
    pub fn ready(&self, key: &K, now: Instant) -> bool {
        self.entries.get(key).is_none_or(|e| now >= e.next_due)
    }

    /// `ready`, or a permitted bypass: `bypass` (a federate call with a
    /// fresh wallet claim) lets the attempt through when the key's last
    /// dispatch is at least `FEDERATE_BYPASS_FLOOR` old.
    pub fn ready_or_bypass(&self, key: &K, now: Instant, bypass: bool) -> bool {
        if self.ready(key, now) {
            return true;
        }
        bypass
            && self.entries.get(key).is_none_or(|e| {
                e.last_dispatch
                    .is_none_or(|t| now.saturating_duration_since(t) >= FEDERATE_BYPASS_FLOOR)
            })
    }

    /// Insert or fetch `key`'s entry, evicting the entry with the EARLIEST
    /// `next_due` when the map is full (it is the closest to due anyway, so
    /// evicting it loses the least).
    fn upsert(&mut self, key: K, now: Instant) -> &mut ThrottleEntry {
        if !self.entries.contains_key(&key) && self.entries.len() >= self.cap {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.next_due)
                .map(|(k, _)| k.clone());
            if let Some(v) = victim {
                self.entries.remove(&v);
            }
        }
        self.entries.entry(key).or_insert(ThrottleEntry {
            next_due: now,
            failures: 0,
            last_dispatch: None,
        })
    }

    /// Stamp a dispatch: requests for `key` were just SENT. Call only after
    /// every early return of the trigger (no claim, no candidates, a cap),
    /// never before — a stamp for an attempt that never happened burns a
    /// backoff step for nothing.
    pub fn on_dispatch(&mut self, key: K, now: Instant, jitter: f64) {
        let max = self.backoff_max;
        let e = self.upsert(key, now);
        e.failures = e.failures.saturating_add(1);
        e.next_due = later(now, jittered(backoff(e.failures, max), jitter));
        e.last_dispatch = Some(now);
    }

    /// The session reached COMPLETE: forget the key.
    pub fn on_complete(&mut self, key: &K) {
        self.entries.remove(key);
    }

    /// The session admitted new content but stopped before the end: retry
    /// soon, with the backoff reset.
    pub fn on_accepted_incomplete(&mut self, key: K, now: Instant) {
        let e = self.upsert(key, now);
        e.failures = 0;
        e.next_due = later(now, BASE_RETRY);
    }

    /// The attempt proved the channel in sync (verified, nothing new): next
    /// attempt after `in_sync_recheck ± 20 %`, backoff reset.
    pub fn on_in_sync(&mut self, key: K, now: Instant, jitter: f64) {
        let recheck = self.in_sync_recheck;
        let e = self.upsert(key, now);
        e.failures = 0;
        e.next_due = later(now, jittered(recheck, jitter));
    }

    /// Drop entries idle for longer than `next_due + backoff_max` (they
    /// would be due anyway; no entry == due). Returns how many were removed.
    pub fn prune(&mut self, now: Instant) -> usize {
        let before = self.entries.len();
        let idle = self.backoff_max;
        self.entries.retain(|_, e| e.next_due.checked_add(idle).is_none_or(|end| now < end));
        before - self.entries.len()
    }

    /// Number of tracked keys (tests).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The key's entry (tests).
    #[cfg(test)]
    pub fn entry(&self, key: &K) -> Option<ThrottleEntry> {
        self.entries.get(key).copied()
    }

    /// Overwrite a key's entry (tests: age a stamp without sleeping).
    #[cfg(test)]
    pub fn set_entry_for_test(&mut self, key: K, entry: ThrottleEntry) {
        self.entries.insert(key, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: fn(u64) -> Duration = Duration::from_secs;

    // ---------------- GCRA ----------------

    #[test]
    fn gcra_refills_after_burst_over_refill() {
        // 100 units, 3600/h → 1 unit per second, full refill in 100 s.
        let g = Gcra::new(100, 3_600);
        let t0 = Instant::now();
        assert!(g.admit(None, t0));
        let tat = g.charge(None, 100, t0);
        assert!(!g.admit(Some(tat), t0), "a spent burst is refused");
        assert!(g.admit(Some(tat), t0 + S(100)), "full refill after burst/refill");
        // A fresh full burst is available again at that point.
        let tat = g.charge(Some(tat), 99, t0 + S(100));
        assert!(g.admit(Some(tat), t0 + S(100)), "99 of 100 spent → still admitted");
    }

    #[test]
    fn gcra_partial_refill_is_proportional() {
        let g = Gcra::new(100, 3_600);
        let t0 = Instant::now();
        let tat = g.charge(None, 100, t0);
        // After 10 s, 10 units are back: 9 more fit, the 10th leaves debt
        // exactly at the tolerance → refused.
        let t = t0 + S(10);
        assert!(g.admit(Some(tat), t));
        let tat2 = g.charge(Some(tat), 9, t);
        assert!(g.admit(Some(tat2), t));
        let tat3 = g.charge(Some(tat2), 1, t);
        assert!(!g.admit(Some(tat3), t));
    }

    #[test]
    fn idle_time_never_banks_more_than_one_burst() {
        let g = Gcra::new(100, 3_600);
        let t0 = Instant::now();
        let tat = g.charge(None, 10, t0); // tat = t0 + 10 s
        // Idle for 1,000 s: the bucket is full (100), not 1,090 units.
        let later = t0 + S(1_000);
        let tat = g.charge(Some(tat), 150, later);
        assert!(!g.admit(Some(tat), later), "a 150-unit spend after idling leaves debt beyond the burst");
        assert_eq!(tat, later + S(150));
    }

    #[test]
    fn gcra_slow_refill_still_refused_a_minute_later() {
        // Negative control for the refill rate: 1 unit per hour.
        let g = Gcra::new(10, 1);
        let t0 = Instant::now();
        let tat = g.charge(None, 10, t0);
        assert!(!g.admit(Some(tat), t0 + S(60)), "1/h refill: still refused after 1 min");
        assert!(g.admit(Some(tat), t0 + S(3_600) + Duration::from_millis(1)), "admitted after one unit refilled");
    }

    #[test]
    fn gcra_concurrent_admits_create_debt_that_is_paid_off() {
        let g = Gcra::new(100, 3_600);
        let t0 = Instant::now();
        // Two requests admitted together on a fresh bucket, both charged.
        assert!(g.admit(None, t0));
        assert!(g.admit(None, t0));
        let tat = g.charge(None, 80, t0);
        let tat = g.charge(Some(tat), 80, t0);
        // Debt of 160 s > tolerance 100 s: refused until 60 s of debt drain.
        assert!(!g.admit(Some(tat), t0 + S(59)));
        assert!(g.admit(Some(tat), t0 + S(61)));
    }

    #[test]
    fn gcra_huge_charge_is_clamped_and_never_panics() {
        let g = Gcra::new(100, 3_600);
        let t0 = Instant::now();
        let tat = g.charge(None, u64::MAX, t0);
        assert_eq!(tat, t0 + S(200), "debt clamped to 2 × tolerance");
        let tat = g.charge(Some(tat), u64::MAX, t0);
        assert_eq!(tat, t0 + S(200), "repeated huge charges stay clamped");
        // Extreme parameters do not panic either.
        let g = Gcra::new(u64::MAX, 1);
        let _ = g.charge(None, u64::MAX, t0);
        let g = Gcra::new(0, 0);
        assert!(g.admit(None, t0));
        let _ = g.charge(None, 1, t0);
    }

    // ---------------- BudgetMap ----------------

    #[test]
    fn full_map_prunes_refilled_buckets_on_demand_so_a_flood_cannot_lock_out_newcomers() {
        let g = Gcra::new(100, 3_600);
        let t0 = Instant::now();
        let mut m: BudgetMap<u32> = BudgetMap::new(3);
        for k in 0..3 {
            m.charge(k, 1, &g, t0);
        }
        m.charge(0, 500, &g, t0); // key 0 stays in debt
        assert_eq!(m.admit(&9, &g, t0), Err(Refusal::MapFull));
        // 2 s later the one-unit keys have refilled: no periodic prune ran,
        // yet a newcomer is admitted and the debtor survived.
        assert_eq!(m.admit(&9, &g, t0 + S(2)), Ok(()));
        assert_eq!(m.len(), 1);
        assert_eq!(m.admit(&0, &g, t0 + S(2)), Err(Refusal::OverBudget));
    }

    #[test]
    fn prune_removes_only_full_buckets_and_a_peer_in_debt_survives() {
        let g = Gcra::new(100, 3_600);
        let t0 = Instant::now();
        let mut m: BudgetMap<u32> = BudgetMap::new(10);
        m.charge(1, 150, &g, t0); // overspent: tat = t0 + 150 s
        m.charge(2, 5, &g, t0); // tat = t0 + 5 s
        assert_eq!(m.prune(t0 + S(6)), 1, "only the refilled bucket is dropped");
        assert!(m.tat(&2).is_none());
        assert!(m.tat(&1).is_some(), "a peer in debt is never pruned");
        assert_eq!(m.admit(&1, &g, t0 + S(6)), Err(Refusal::OverBudget));
    }

    #[test]
    fn the_old_fifo_eviction_bypass_no_longer_refills_anyone() {
        // Negative control for the pre-0.141.0 Sybil bypass: a victim that
        // spent its budget, followed by a flood of fresh identities. The
        // victim is never evicted; the flood is refused at the cap instead.
        let g = Gcra::new(100, 1); // effectively no refill during the test
        let t0 = Instant::now();
        let cap = 1_000;
        let mut m: BudgetMap<u32> = BudgetMap::new(cap);
        m.charge(0, 100, &g, t0);
        let mut refused = 0;
        for id in 1..=(cap as u32 * 3) {
            match m.admit(&id, &g, t0) {
                Ok(()) => m.charge(id, 1, &g, t0),
                Err(Refusal::MapFull) => refused += 1,
                Err(e) => panic!("unexpected {e:?}"),
            }
            m.prune(t0);
        }
        assert!(refused > 0, "the flood must hit the cap");
        assert_eq!(m.len(), cap, "map stays bounded");
        assert_eq!(m.admit(&0, &g, t0), Err(Refusal::OverBudget), "victim's debt survives the flood");
    }

    #[test]
    fn full_map_refuses_new_keys_but_not_existing_ones() {
        let g = Gcra::new(100, 3_600);
        let t0 = Instant::now();
        let mut m: BudgetMap<u32> = BudgetMap::new(2);
        m.charge(1, 10, &g, t0);
        m.charge(2, 10, &g, t0);
        assert_eq!(m.admit(&3, &g, t0), Err(Refusal::MapFull));
        assert_eq!(m.admit(&1, &g, t0), Ok(()), "existing keys unaffected");
        // Once a bucket refills, pruning frees a slot for the newcomer.
        m.prune(t0 + S(11));
        assert_eq!(m.admit(&3, &g, t0 + S(11)), Ok(()));
    }

    #[test]
    fn spraying_channel_ids_is_bounded_and_cleared_by_prune() {
        // Reconcile keys include a requester-chosen channel_id; an unknown
        // channel charges 1 unit. 100k sprayed ids stay bounded by the cap
        // and are gone after one prune once their single unit refilled.
        let g = Gcra::new(200_000, 10_000); // 0.36 s per unit
        let t0 = Instant::now();
        let cap = 200_000;
        let mut m: BudgetMap<(u8, u64)> = BudgetMap::new(cap);
        for cid in 0..300_000u64 {
            if m.admit(&(1, cid), &g, t0).is_ok() {
                m.charge((1, cid), 1, &g, t0);
            }
        }
        assert_eq!(m.len(), cap);
        assert_eq!(m.prune(t0 + S(1)), cap);
        assert!(m.is_empty());
    }

    #[test]
    fn honest_peer_never_refused_among_a_thousand_sybils() {
        let g = Gcra::new(20_000, 5_000);
        let t0 = Instant::now();
        let mut m: BudgetMap<u32> = BudgetMap::new(100_000);
        let honest = 0u32;
        // 7 days of 30 s ticks: every Sybil spends its maximum every tick,
        // the honest peer spends a normal 300 units every 10 minutes.
        for tick in 0..(7 * 24 * 120u64) {
            let now = t0 + S(tick * 30);
            for sybil in 1..=1_000u32 {
                if m.admit(&sybil, &g, now).is_ok() {
                    m.charge(sybil, 20_000, &g, now);
                }
            }
            if tick % 20 == 0 {
                assert_eq!(m.admit(&honest, &g, now), Ok(()), "honest refused at tick {tick}");
                m.charge(honest, 300, &g, now);
            }
            if tick % 1_000 == 0 {
                m.prune(now);
            }
        }
        // Negative control: with a map too small to hold the Sybils, a NEW
        // honest key is refused — the per-key buckets are what isolate it.
        let mut small: BudgetMap<u32> = BudgetMap::new(1_000);
        for sybil in 1..=1_000u32 {
            small.charge(sybil, 20_000, &g, t0);
        }
        assert_eq!(small.admit(&honest, &g, t0), Err(Refusal::MapFull));
    }

    // ---------------- AttemptThrottle ----------------

    fn throttle() -> AttemptThrottle<u64> {
        AttemptThrottle::new(MAX_THROTTLE_KEYS, S(30 * 60), S(60 * 60))
    }

    #[test]
    fn backoff_sequence_and_cap() {
        let max = S(30 * 60);
        let seq: Vec<u64> = (1..=9).map(|f| backoff(f, max).as_secs()).collect();
        assert_eq!(seq, vec![30, 60, 120, 240, 480, 960, 1_800, 1_800, 1_800]);
        assert_eq!(backoff(u32::MAX, max), max, "no overflow");
        assert_eq!(backoff(0, max), S(30));
        // The stamped next_due follows the sequence (no jitter).
        let mut t = throttle();
        let t0 = Instant::now();
        for (i, want) in [30u64, 60, 120, 240, 480, 960, 1_800, 1_800].iter().enumerate() {
            t.on_dispatch(7, t0, 0.0);
            assert_eq!(t.entry(&7).unwrap().next_due, t0 + S(*want), "dispatch {}", i + 1);
        }
    }

    #[test]
    fn jitter_is_bounded_to_twenty_percent() {
        let d = S(100);
        assert_eq!(jittered(d, 1.0), S(120));
        assert_eq!(jittered(d, -1.0), S(80));
        assert_eq!(jittered(d, 0.0), d);
        assert_eq!(jittered(d, 7.0), S(120), "clamped");
        assert_eq!(jittered(d, -7.0), S(80), "clamped");
        assert_eq!(jittered(d, f64::NAN), d);
        for _ in 0..1_000 {
            let j = random_jitter();
            assert!((-1.0..=1.0).contains(&j));
        }
        let mut t = throttle();
        let t0 = Instant::now();
        t.on_in_sync(1, t0, 1.0);
        assert_eq!(t.entry(&1).unwrap().next_due, t0 + S(72 * 60));
        t.on_in_sync(1, t0, -1.0);
        assert_eq!(t.entry(&1).unwrap().next_due, t0 + S(48 * 60));
    }

    /// 24 h of 30 s sweep ticks on one in-sync channel; `gated` = consult
    /// the throttle (the 0.141.0 gate) or not (pre-0.141.0).
    fn day_of_ticks(gated: bool) -> u32 {
        let t0 = Instant::now();
        let mut t = throttle();
        let mut attempts = 0;
        let mut jitter = -1.0f64;
        for tick in 0..2_880u64 {
            let now = t0 + S(tick * 30);
            if !gated || t.ready(&1, now) {
                attempts += 1;
                t.on_dispatch(1, now, 0.0);
                // Every attempt proves the channel in sync.
                t.on_in_sync(1, now, jitter);
                jitter = if jitter >= 1.0 { -1.0 } else { jitter + 0.5 };
            }
        }
        attempts
    }

    #[test]
    fn a_day_of_sweep_ticks_on_an_in_sync_channel_costs_about_two_dozen_attempts() {
        let attempts = day_of_ticks(true);
        assert!((20..=31).contains(&attempts), "attempts = {attempts}");
        // Negative control: without the gate every tick is an attempt.
        assert_eq!(day_of_ticks(false), 2_880);
    }

    #[test]
    fn accepted_resets_the_backoff_and_complete_clears() {
        let t0 = Instant::now();
        let mut t = throttle();
        for _ in 0..6 {
            t.on_dispatch(1, t0, 0.0);
        }
        assert_eq!(t.entry(&1).unwrap().failures, 6);
        t.on_accepted_incomplete(1, t0);
        let e = t.entry(&1).unwrap();
        assert_eq!((e.failures, e.next_due), (0, t0 + BASE_RETRY));
        t.on_dispatch(1, t0, 0.0);
        assert_eq!(t.entry(&1).unwrap().next_due, t0 + S(30), "backoff restarts from the first step");
        t.on_complete(&1);
        assert!(t.entry(&1).is_none());
        assert!(t.ready(&1, t0), "no entry == due");
    }

    #[test]
    fn federate_bypass_respects_the_floor() {
        let t0 = Instant::now();
        let mut t = throttle();
        t.on_dispatch(1, t0, 0.0);
        t.on_in_sync(1, t0, 0.0); // next_due = t0 + 60 min
        let early = t0 + S(59);
        assert!(!t.ready(&1, early));
        assert!(!t.ready_or_bypass(&1, early, true), "bypass refused inside the floor");
        assert!(!t.ready_or_bypass(&1, t0 + S(120), false), "no bypass without a fresh claim");
        assert!(t.ready_or_bypass(&1, t0 + S(60), true), "bypass allowed at the floor");
        // A key with no dispatch on record (outcome-created) may bypass.
        let mut t = throttle();
        t.on_in_sync(2, t0, 0.0);
        assert!(t.ready_or_bypass(&2, t0, true));
    }

    #[test]
    fn map_cap_evicts_the_earliest_next_due() {
        let t0 = Instant::now();
        let mut t: AttemptThrottle<u64> = AttemptThrottle::new(3, S(1_800), S(3_600));
        t.on_in_sync(1, t0, 0.0); // due t0 + 60 min
        t.on_dispatch(2, t0, 0.0); // due t0 + 30 s  ← earliest
        t.on_accepted_incomplete(3, t0 + S(5)); // due t0 + 35 s
        t.on_dispatch(4, t0, 0.0);
        assert_eq!(t.len(), 3);
        assert!(t.entry(&2).is_none(), "the earliest-due entry is evicted");
        assert!(t.entry(&1).is_some() && t.entry(&3).is_some() && t.entry(&4).is_some());
    }

    #[test]
    fn absurd_durations_never_panic() {
        let t0 = Instant::now();
        let mut t: AttemptThrottle<u64> = AttemptThrottle::new(4, Duration::MAX, Duration::MAX);
        t.on_dispatch(1, t0, 1.0);
        t.on_in_sync(2, t0, 1.0);
        t.on_accepted_incomplete(3, t0);
        assert_eq!(t.prune(t0), 0);
        assert!(!t.ready(&2, t0));
        assert_eq!(jittered(Duration::MAX, 1.0), Duration::MAX);
    }

    #[test]
    fn prune_drops_only_long_idle_entries() {
        let t0 = Instant::now();
        let mut t = throttle();
        t.on_dispatch(1, t0, 0.0); // due t0 + 30 s
        t.on_in_sync(2, t0, 0.0); // due t0 + 60 min
        assert_eq!(t.prune(t0 + S(30 + 1_799)), 0);
        assert_eq!(t.prune(t0 + S(30 + 1_800)), 1);
        assert!(t.entry(&2).is_some());
    }

    // ---------------- Long-run simulation ----------------

    /// Two nodes, 15 public channels, 7 days of 30 s sweep ticks with an
    /// injected clock — the requester runs the throttle, the responder the
    /// default reconcile budget per (peer, channel). Channel 1 is large (a
    /// full worst-case first page); the rest are small. A gap is injected
    /// on day 3. Mirrors `maybe_trigger_backfill` + `channel_backfill_due`.
    #[test]
    fn seven_day_simulation_never_caps_the_honest_peer_and_repairs_a_gap_quickly() {
        let t0 = Instant::now();
        let gcra = Gcra::new(200_000, 10_000);
        let mut budget: BudgetMap<u64> = BudgetMap::new(200_000);
        let mut throttle: AttemptThrottle<u64> =
            AttemptThrottle::new(MAX_THROTTLE_KEYS, S(30 * 60), S(60 * 60));
        let catchup = S(6 * 3_600);
        let cost = |cid: u64| if cid == 1 { 1_000 + 2_300 } else { 40 };
        let mut completed_at: HashMap<u64, Instant> = HashMap::new();
        let mut gap: Option<(u64, Instant)> = None;
        let mut repaired_after: Option<Duration> = None;
        let mut capped = 0u32;
        let mut attempts = 0u32;
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for tick in 0..(7 * 24 * 120u64) {
            let now = t0 + S(tick * 30);
            if tick == 3 * 24 * 120 + 17 {
                gap = Some((5, now));
            }
            if tick % 120 == 0 {
                budget.prune(now);
                throttle.prune(now);
            }
            for cid in 1..=15u64 {
                let due = completed_at.get(&cid).is_none_or(|c| now.duration_since(*c) >= catchup);
                if !(due && throttle.ready(&cid, now)) {
                    continue;
                }
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let jitter = ((seed >> 11) as f64 / (1u64 << 53) as f64) * 2.0 - 1.0;
                throttle.on_dispatch(cid, now, jitter);
                attempts += 1;
                if budget.admit(&cid, &gcra, now).is_err() {
                    capped += 1;
                    continue;
                }
                budget.charge(cid, cost(cid), &gcra, now);
                // The very first sync of every channel admits real content.
                let first = tick == 0;
                let gap_here = gap.is_some_and(|(g, _)| g == cid);
                if first || gap_here {
                    throttle.on_complete(&cid);
                    completed_at.insert(cid, now);
                    if gap_here {
                        repaired_after = Some(now.duration_since(gap.unwrap().1));
                        gap = None;
                    }
                } else {
                    throttle.on_in_sync(cid, now, jitter);
                }
            }
        }
        assert_eq!(capped, 0, "the default budget never caps the honest peer");
        let repaired = repaired_after.expect("gap repaired");
        assert!(repaired <= S(72 * 60), "gap repaired within in_sync_recheck + jitter: {repaired:?}");
        // ~15 channels × ~24 attempts/day × 7 days, far below 15 × 2,880 × 7.
        assert!(attempts < 15 * 30 * 7, "attempts = {attempts}");
        // Restart: an empty throttle is due immediately (pre-0.141 behaviour).
        let fresh: AttemptThrottle<u64> = AttemptThrottle::new(10, S(1_800), S(3_600));
        assert!(fresh.ready(&1, t0 + S(1)));
    }
}
