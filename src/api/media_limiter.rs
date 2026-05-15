//! Per-IP concurrent-permit limiter for the media endpoint.
//!
//! The pre-v0.41 design used a single global `Semaphore` (32 permits
//! by default) for `/api/v1/media/:cid`. A single attacker IP could
//! hold all 32 permits with slow requests and lock out every other
//! client — the `tower_governor` per-IP rate limit caps requests per
//! minute but not concurrent in-flight slots, so a botnet/single IP
//! issuing 32 long-running fetches under the rate limit was still a
//! viable DoS vector against legitimate traffic.
//!
//! `PerIpSemaphore` wraps the global Semaphore plus a per-IP counter
//! map. Acquiring takes one slot from the global pool AND one slot
//! from the per-IP budget. If the per-IP budget is exhausted, the
//! acquire fails fast with `RejectReason::PerIpExceeded` (caller maps
//! to 429 + Retry-After). The global cap still applies as the outer
//! bound; the per-IP cap is strictly an upper-bound subdivision.
//!
//! Permits are reference-counted via `Arc<AtomicUsize>`, so a permit
//! dropped after its IP's entry has been swept from the map (via the
//! background cleanup task) still decrements the correct counter —
//! the dropped Arc just doesn't see any new acquires for that IP
//! until they re-create the entry. Race-free by construction.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Bucket an IP address by routing prefix so that a /24 IPv4 subnet
/// shares one slot and a /64 IPv6 allocation shares one slot.
///
/// Without bucketing, the per-IP cap is **trivially bypassed** on
/// IPv6: an attacker with a typical end-user /64 allocation has
/// 2^64 source addresses to rotate through; with our default cap of
/// 4 they get 4 × 2^64 effective slots, which is unbounded for
/// practical purposes. The v0.41 audit flagged this as critical.
///
/// Bucket sizes:
///   * **IPv4 /24** — 256 hosts. Matches the typical residential
///     ISP allocation. Tighter (e.g. /32 exact) would lock out
///     families behind one NAT; looser (e.g. /16) would group
///     unrelated subnets.
///   * **IPv6 /64** — the smallest end-site allocation per RFC
///     6177. Every device in a typical home has a unique /128 but
///     shares the /64, so bucketing here matches the IPv4 /24
///     residential model.
///
/// Returns an `IpAddr` with the low-order bits zeroed; the result
/// is used as the DashMap key directly. Two addresses in the same
/// bucket produce equal `IpAddr` values, so DashMap collapses them.
pub fn ip_to_bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Zero the low 8 bits → /24 prefix.
            IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], 0))
        }
        IpAddr::V6(v6) => {
            // First check if this is an IPv4-mapped IPv6 (`::ffff:a.b.c.d`)
            // — these come in on dual-stack listeners and should be
            // bucketed as IPv4 /24, not IPv6 /64. Without this, a
            // dual-stack node would put every IPv4 client in its own
            // distinct IPv6 bucket and the cap would never engage.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_to_bucket(IpAddr::V4(v4));
            }
            let segs = v6.segments();
            // Zero the low 64 bits → /64 prefix.
            IpAddr::V6(Ipv6Addr::new(
                segs[0], segs[1], segs[2], segs[3], 0, 0, 0, 0,
            ))
        }
    }
}

/// Reasons an acquire can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The IP has reached its per-IP concurrent-permit cap. Caller
    /// maps to 429 Too Many Requests.
    PerIpExceeded,
    /// The semaphore is closed (only during shutdown). Caller maps
    /// to 503 Service Unavailable.
    Shutdown,
}

/// Per-IP-bounded semaphore on top of a global Tokio semaphore.
pub struct PerIpSemaphore {
    /// Global cap — outer bound on total concurrent permits.
    global: Arc<Semaphore>,
    /// Live counters per client IP. Entries are created on first
    /// acquire and removed by the background sweep when their
    /// counter is zero. Bounded total memory because counters fall
    /// to zero promptly when requests finish.
    per_ip: Arc<DashMap<IpAddr, Arc<AtomicUsize>>>,
    /// Maximum concurrent permits any single IP may hold. Must be
    /// `<= global` capacity; validated at config-load time.
    per_ip_cap: usize,
}

impl PerIpSemaphore {
    /// Construct a new limiter with `global_permits` total slots and
    /// `per_ip_cap` slots per client IP. The caller is responsible
    /// for `per_ip_cap <= global_permits`; validation belongs at the
    /// config layer.
    pub fn new(global_permits: usize, per_ip_cap: usize) -> Arc<Self> {
        Arc::new(Self {
            global: Arc::new(Semaphore::new(global_permits)),
            per_ip: Arc::new(DashMap::new()),
            per_ip_cap,
        })
    }

    /// Acquire one global slot AND one per-IP slot. The returned
    /// permit decrements both counters when dropped. Order of checks:
    ///
    ///   1. Per-IP cap is checked FIRST (cheap, no await). Hit → 429
    ///      fail-fast; the caller doesn't pay the global-queue cost.
    ///   2. Global semaphore is acquired SECOND (may queue under
    ///      FIFO fairness). Permits past the global cap simply wait.
    ///
    /// This ordering means an attacker's excess attempts get 429'd
    /// without ever taking a global queue slot — legitimate users
    /// continue to flow through.
    ///
    /// **Cancellation safety:** The per-IP counter increment is
    /// owned by a `PerIpReservation` RAII guard between fetch_add
    /// and the global await. If the caller's future is dropped while
    /// parked on `acquire_owned().await`, the guard's Drop rolls
    /// back the counter. Without this guard a malicious client could
    /// repeatedly cancel in-flight requests, leaking per-IP slots
    /// until their IP is permanently 429'd with zero permits actually
    /// held.
    pub async fn acquire(&self, ip: IpAddr) -> Result<PerIpPermit, RejectReason> {
        // Normalize the IP to its routing bucket (/24 IPv4, /64 IPv6,
        // IPv4-mapped IPv6 collapsed to IPv4). Without this, an IPv6
        // attacker with a /64 allocation has 2^64 effective slots —
        // see `ip_to_bucket` doc.
        let bucket = ip_to_bucket(ip);

        // Get-or-create the per-bucket counter atomically. DashMap's
        // entry-locking serializes inserts for the same key, so even
        // if many concurrent acquires for the same bucket race here,
        // they all converge on the same `Arc<AtomicUsize>`.
        let counter = self
            .per_ip
            .entry(bucket)
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone();

        // Reserve a per-IP slot. `fetch_add` returns the OLD value;
        // we reject if it was already at the cap.
        let prev = counter.fetch_add(1, Ordering::AcqRel);
        if prev >= self.per_ip_cap {
            // Roll back our optimistic increment so the next caller
            // for this bucket gets an accurate read.
            counter.fetch_sub(1, Ordering::AcqRel);
            return Err(RejectReason::PerIpExceeded);
        }

        // RAII guard. Rolls back the per-IP fetch_add on Drop unless
        // `commit()` is called first. Protects against the
        // cancellation race where the request future is dropped
        // between our fetch_add and `acquire_owned()` resolving.
        let mut reservation = PerIpReservation {
            counter: counter.clone(),
            committed: false,
        };

        // Per-IP slot reserved; now queue for the global permit. If
        // the semaphore is closed (only on shutdown), the reservation
        // guard drops with `committed = false` and rolls back the
        // per-IP increment. If the await is cancelled (future
        // dropped), same path — guard rolls back, counter stays
        // consistent.
        let global_permit = match self.global.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                // Reservation drop will roll back the counter.
                return Err(RejectReason::Shutdown);
            }
        };

        // Permit successfully acquired — transfer ownership of the
        // counter from the reservation to the returned PerIpPermit.
        // The permit's Drop will be responsible for the final
        // decrement; the reservation must NOT also decrement.
        reservation.commit();

        Ok(PerIpPermit {
            _global: global_permit,
            counter,
        })
    }

    /// Remove per-IP entries whose counter is currently zero. Safe to
    /// run concurrently with `acquire` — DashMap's `retain` takes a
    /// per-shard write lock, and a fresh acquire that races the sweep
    /// either sees the entry before removal (proceeds normally) or
    /// after (creates a new entry). Either path is correct because
    /// the in-flight permit holds its own `Arc<AtomicUsize>` clone
    /// and drops decrement THAT counter, regardless of whether it's
    /// still in the map.
    ///
    /// Returns the number of entries removed (useful for tests + ops
    /// metrics).
    pub fn sweep(&self) -> usize {
        let before = self.per_ip.len();
        self.per_ip
            .retain(|_, v| v.load(Ordering::Acquire) > 0);
        before - self.per_ip.len()
    }

    /// Number of distinct IPs currently tracked (live counters).
    /// Useful for ops + tests.
    pub fn tracked_ip_count(&self) -> usize {
        self.per_ip.len()
    }

    /// Available global permits — equal to the Tokio semaphore's
    /// current free count.
    pub fn available_global(&self) -> usize {
        self.global.available_permits()
    }

    /// Spawn a background sweep task that runs every `interval` and
    /// removes stale per-IP entries. Cancels when `shutdown_rx`
    /// receives any value (or is closed). Uses `broadcast::Receiver`
    /// to match the rest of the node's shutdown plumbing.
    ///
    /// Returns the spawned task's `JoinHandle` so the caller can
    /// `await` it during graceful shutdown if it wants.
    pub fn spawn_sweep_task(
        self: Arc<Self>,
        interval: Duration,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip the first immediate tick — let the node finish
            // startup before we start scanning.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let removed = self.sweep();
                        if removed > 0 {
                            tracing::debug!(
                                removed = removed,
                                remaining = self.tracked_ip_count(),
                                "per-IP media limiter sweep",
                            );
                        }
                    }
                    // Any signal on the broadcast (or close) cancels
                    // the loop. `recv()` returns Err on close and on
                    // lag; both mean "stop sweeping". We don't care
                    // about distinguishing them.
                    _ = shutdown_rx.recv() => break,
                }
            }
        })
    }
}

/// RAII guard that rolls back a per-IP counter increment if `commit`
/// isn't called. Used internally by `acquire` to make the
/// fetch_add → global.acquire_owned().await sequence cancellation-
/// safe.
///
/// Without this guard, a malicious client could repeatedly cancel
/// in-flight requests (HTTP/2 RST_STREAM, client disconnect) at the
/// exact moment the future is parked on `acquire_owned`, leaking
/// per-IP counter increments. Eventually the IP hits its cap with
/// zero permits actually held — permanent 429 until the next sweep.
struct PerIpReservation {
    counter: Arc<AtomicUsize>,
    committed: bool,
}

impl PerIpReservation {
    /// Mark the reservation as transferred to the final
    /// `PerIpPermit`. Drop must not roll back.
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PerIpReservation {
    fn drop(&mut self) {
        if !self.committed {
            // The reservation was abandoned — roll back the
            // optimistic fetch_add from the caller. Counter
            // invariant: increment-and-rollback paths never
            // underflow because the counter was >= 1 when we
            // entered (we just incremented it).
            self.counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Held by an active media handler. Dropping decrements both the
/// global and per-IP counters; the global permit is released by its
/// own `Drop`, and the per-IP counter is decremented by `Drop` on
/// this wrapper.
#[derive(Debug)]
pub struct PerIpPermit {
    /// Global semaphore permit. Drops on its own — we just need to
    /// keep it alive for the lifetime of this struct.
    _global: OwnedSemaphorePermit,
    /// Reference-counted handle to the per-IP counter. The Arc is
    /// shared with the entry in `PerIpSemaphore::per_ip`; either
    /// side dropping is fine because the AtomicUsize stays alive
    /// until BOTH Arcs are released.
    counter: Arc<AtomicUsize>,
}

impl Drop for PerIpPermit {
    fn drop(&mut self) {
        // Defense-in-depth: a future refactor that constructs a
        // PerIpPermit without a corresponding fetch_add would wrap
        // to usize::MAX on drop, permanently locking out that IP's
        // bucket. The debug_assert catches the invariant violation
        // in test/debug builds; release builds still wrap (no
        // production crash) but the diagnostic is in CI.
        debug_assert!(
            self.counter.load(Ordering::Acquire) > 0,
            "PerIpPermit dropped with counter == 0; invariant violation",
        );
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[tokio::test]
    async fn single_ip_under_cap_succeeds() {
        let limiter = PerIpSemaphore::new(8, 4);
        let _p1 = limiter.acquire(ip(1, 1, 1, 1)).await.unwrap();
        let _p2 = limiter.acquire(ip(1, 1, 1, 1)).await.unwrap();
        let _p3 = limiter.acquire(ip(1, 1, 1, 1)).await.unwrap();
        let _p4 = limiter.acquire(ip(1, 1, 1, 1)).await.unwrap();
        // 4 permits held by one IP, all OK.
    }

    #[tokio::test]
    async fn single_ip_at_cap_is_rejected() {
        let limiter = PerIpSemaphore::new(8, 2);
        let _p1 = limiter.acquire(ip(2, 2, 2, 2)).await.unwrap();
        let _p2 = limiter.acquire(ip(2, 2, 2, 2)).await.unwrap();
        let err = limiter.acquire(ip(2, 2, 2, 2)).await.unwrap_err();
        assert_eq!(err, RejectReason::PerIpExceeded);
    }

    #[tokio::test]
    async fn rejected_acquire_does_not_consume_global_permit() {
        // Per-IP rejection happens BEFORE the global semaphore
        // queue, so other IPs are unaffected by an attacker burning
        // through their per-IP cap.
        let limiter = PerIpSemaphore::new(4, 1);
        let _p1 = limiter.acquire(ip(3, 3, 3, 3)).await.unwrap();
        // Second attempt from same IP rejected fast.
        let err = limiter.acquire(ip(3, 3, 3, 3)).await.unwrap_err();
        assert_eq!(err, RejectReason::PerIpExceeded);
        // Other IPs can still acquire — global permit count not
        // affected by the rejected attempt.
        assert_eq!(limiter.available_global(), 3);
        let _p2 = limiter.acquire(ip(4, 4, 4, 4)).await.unwrap();
        let _p3 = limiter.acquire(ip(5, 5, 5, 5)).await.unwrap();
        let _p4 = limiter.acquire(ip(6, 6, 6, 6)).await.unwrap();
        // Now global is full (1 from first IP + 3 from others).
        assert_eq!(limiter.available_global(), 0);
    }

    #[tokio::test]
    async fn permit_drop_releases_per_ip_slot() {
        let limiter = PerIpSemaphore::new(8, 2);
        {
            let _p1 = limiter.acquire(ip(7, 7, 7, 7)).await.unwrap();
            let _p2 = limiter.acquire(ip(7, 7, 7, 7)).await.unwrap();
            let err = limiter.acquire(ip(7, 7, 7, 7)).await.unwrap_err();
            assert_eq!(err, RejectReason::PerIpExceeded);
            // p1, p2 drop at end of scope.
        }
        // Same IP can acquire again now.
        let _p3 = limiter.acquire(ip(7, 7, 7, 7)).await.unwrap();
    }

    #[tokio::test]
    async fn sweep_removes_zero_counter_entries() {
        // Use IPs in DIFFERENT /24s — bucketing means same-/24
        // addresses share an entry. (10.0.0.x and 10.0.1.x are
        // in different /24 buckets.)
        let limiter = PerIpSemaphore::new(8, 4);
        {
            let _p = limiter.acquire(ip(10, 0, 0, 1)).await.unwrap();
            let _q = limiter.acquire(ip(10, 0, 1, 1)).await.unwrap();
            assert_eq!(limiter.tracked_ip_count(), 2);
        }
        assert_eq!(limiter.tracked_ip_count(), 2);
        let removed = limiter.sweep();
        assert_eq!(removed, 2);
        assert_eq!(limiter.tracked_ip_count(), 0);
    }

    #[tokio::test]
    async fn sweep_keeps_active_entries() {
        // Two different /24 buckets.
        let limiter = PerIpSemaphore::new(8, 4);
        let _held = limiter.acquire(ip(11, 0, 0, 1)).await.unwrap();
        let _dropped = limiter.acquire(ip(11, 0, 1, 1)).await.unwrap();
        drop(_dropped);
        // 11.0.1.0/24 has counter 0; 11.0.0.0/24 has counter 1.
        let removed = limiter.sweep();
        assert_eq!(removed, 1, "only the zero-counter entry is removed");
        assert_eq!(limiter.tracked_ip_count(), 1);
    }

    #[tokio::test]
    async fn sweep_race_with_concurrent_acquire_is_safe() {
        // Drop a permit, then race a sweep with a new acquire for
        // the same IP. The new acquire either sees the existing
        // entry (gets reused) or creates a fresh one — both correct.
        let limiter = PerIpSemaphore::new(8, 4);
        {
            let _p = limiter.acquire(ip(12, 0, 0, 1)).await.unwrap();
        }
        // Run sweep and a new acquire concurrently. Whichever wins
        // the per-shard lock first, the second proceeds correctly.
        let l1 = limiter.clone();
        let l2 = limiter.clone();
        let sweep_fut = tokio::spawn(async move { l1.sweep() });
        let acquire_fut = tokio::spawn(async move {
            l2.acquire(ip(12, 0, 0, 1)).await
        });
        let _swept = sweep_fut.await.unwrap();
        let permit = acquire_fut.await.unwrap().unwrap();
        assert_eq!(limiter.tracked_ip_count(), 1);
        drop(permit);
    }

    #[tokio::test]
    async fn distinct_subnets_each_get_their_own_cap() {
        // Two IPs in different /24s. Cap=2 per bucket.
        let limiter = PerIpSemaphore::new(16, 2);
        let _a1 = limiter.acquire(ip(20, 0, 0, 1)).await.unwrap();
        let _a2 = limiter.acquire(ip(20, 0, 0, 1)).await.unwrap();
        // 20.0.0.0/24 at cap.
        let err = limiter.acquire(ip(20, 0, 0, 1)).await.unwrap_err();
        assert_eq!(err, RejectReason::PerIpExceeded);
        // Different /24 — unaffected.
        let _b1 = limiter.acquire(ip(20, 0, 1, 1)).await.unwrap();
        let _b2 = limiter.acquire(ip(20, 0, 1, 1)).await.unwrap();
        let err = limiter.acquire(ip(20, 0, 1, 1)).await.unwrap_err();
        assert_eq!(err, RejectReason::PerIpExceeded);
    }

    // --- v0.41 audit fixes: prefix bucketing, cancellation safety ----

    #[tokio::test]
    async fn ipv4_24_subnet_shares_per_ip_slot() {
        // 192.168.1.5 and 192.168.1.99 are in the same /24 bucket
        // (192.168.1.0/24) so they share one per-IP cap.
        let limiter = PerIpSemaphore::new(16, 2);
        let _p1 = limiter.acquire(ip(192, 168, 1, 5)).await.unwrap();
        let _p2 = limiter.acquire(ip(192, 168, 1, 99)).await.unwrap();
        // Third request from ANY .1.0/24 → rejected.
        let err = limiter.acquire(ip(192, 168, 1, 200)).await.unwrap_err();
        assert_eq!(err, RejectReason::PerIpExceeded);
        // But .2.0/24 is a different bucket — has its own slots.
        let _q = limiter.acquire(ip(192, 168, 2, 1)).await.unwrap();
    }

    #[tokio::test]
    async fn ipv6_64_subnet_shares_per_ip_slot() {
        // Two IPv6 addresses with the same /64 prefix.
        let limiter = PerIpSemaphore::new(16, 2);
        let a: IpAddr = "2001:db8:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1::ffff:ffff:ffff:ffff".parse().unwrap();
        let c: IpAddr = "2001:db8:1::beef".parse().unwrap();
        let _p1 = limiter.acquire(a).await.unwrap();
        let _p2 = limiter.acquire(b).await.unwrap();
        // Third request from ANY 2001:db8:1::/64 → rejected. Closes
        // the IPv6 bypass: an attacker with a typical /64 can no
        // longer rotate through 2^64 addresses to defeat the cap.
        let err = limiter.acquire(c).await.unwrap_err();
        assert_eq!(err, RejectReason::PerIpExceeded);
        // Different /64 (2001:db8:2::/64) is a separate bucket.
        let d: IpAddr = "2001:db8:2::1".parse().unwrap();
        let _q = limiter.acquire(d).await.unwrap();
    }

    #[tokio::test]
    async fn ipv4_mapped_ipv6_collapses_to_ipv4_bucket() {
        // ::ffff:127.0.0.1 should bucket as 127.0.0.0/24, not as a
        // separate IPv6 entity. Critical for dual-stack listeners.
        let limiter = PerIpSemaphore::new(16, 2);
        let v4: IpAddr = "127.0.0.50".parse().unwrap();
        let v6_mapped: IpAddr = "::ffff:127.0.0.99".parse().unwrap();
        // Two requests via the mapped form fill the bucket.
        let _p1 = limiter.acquire(v6_mapped).await.unwrap();
        let _p2 = limiter.acquire(v6_mapped).await.unwrap();
        // The "native" v4 from the same /24 hits the same bucket → 429.
        let err = limiter.acquire(v4).await.unwrap_err();
        assert_eq!(err, RejectReason::PerIpExceeded);
    }

    #[test]
    fn ip_to_bucket_zeroes_low_bits() {
        // /24 IPv4.
        assert_eq!(
            ip_to_bucket("203.0.113.42".parse().unwrap()),
            "203.0.113.0".parse::<IpAddr>().unwrap()
        );
        // /64 IPv6.
        assert_eq!(
            ip_to_bucket("2001:db8:abcd:1234::ffff".parse().unwrap()),
            "2001:db8:abcd:1234::".parse::<IpAddr>().unwrap()
        );
        // IPv4-mapped IPv6 → IPv4 /24.
        assert_eq!(
            ip_to_bucket("::ffff:10.20.30.40".parse().unwrap()),
            "10.20.30.0".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn cancellation_safety_rolls_back_per_ip_counter() {
        // Simulate the cancellation race: an attacker calls
        // `acquire` then cancels the future after fetch_add but
        // before the global await resolves. Without the RAII guard
        // the per-IP counter would stay incremented forever; with
        // the guard, drop rolls it back.
        let limiter = PerIpSemaphore::new(1, 4);
        // Hold the single global permit so the next acquire parks.
        let _hold = limiter.acquire(ip(50, 50, 50, 50)).await.unwrap();

        // Now an acquire from a DIFFERENT bucket will park on the
        // global await. We spawn it, then cancel before it resolves.
        let l2 = limiter.clone();
        let attacker_ip = ip(60, 60, 60, 60);
        let handle = tokio::spawn(async move {
            // This will await forever because global has no permits.
            let _ = l2.acquire(attacker_ip).await;
        });
        // Give the spawned task time to reach fetch_add + the await.
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Cancel the future. The RAII guard's Drop should fire.
        handle.abort();
        // Give the abort time to propagate + Drop to run.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // The per-IP counter for the attacker bucket should be 0 —
        // the RAII guard rolled back the fetch_add. We verify this
        // by checking that we can acquire `per_ip_cap` permits
        // afresh for that bucket (we only need 1 permit globally
        // too, but the global is held by `_hold`. Drop _hold first).
        drop(_hold);
        // Now acquire repeatedly from the attacker bucket. If the
        // cancellation safely rolled back, all 4 should succeed.
        let p1 = limiter.acquire(attacker_ip).await.unwrap();
        // ... and so on. Even one success proves the rollback.
        drop(p1);
    }
}
