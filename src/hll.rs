//! Minimal, wire-stable HyperLogLog for the Hot Topics subsystem (spec 3
//! §3.9, protocol §3.15).
//!
//! Why hand-rolled rather than a crate: the sketch is exchanged **between
//! independent node operators and across node versions**, so its serialized
//! form has to be frozen and reproducible for the life of the protocol. A
//! third-party HLL crate would also require pinning a deterministic
//! `BuildHasher` (its default is randomly seeded) and would give no stability
//! guarantee on its sparse/dense serialization. Here we control both:
//!
//! * **No hashing step.** The only thing ever inserted is a `NewsPost`
//!   `msg_id`, which is already a 32-byte Keccak-256 digest — uniformly
//!   distributed. We slice the leading 64 bits directly; every node derives
//!   the same register update for the same post.
//! * **Fixed dense layout.** `HLL_P = 12` → 4096 one-byte registers. The wire
//!   form is a 1-byte `sketch_format` tag followed by a zstd frame of exactly
//!   `HLL_REGISTERS` bytes. An unknown tag byte means "skip this one tag,
//!   keep processing the digest" (protocol §3.15).
//!
//! Union is register-wise max — associative, commutative and idempotent, so a
//! post gossiped to every node contributes cardinality 1 to the merged
//! estimate regardless of how many digests carried it or in what order.

use std::io::Read;

/// HyperLogLog precision. 4096 registers, ~1.6 % standard error. Fixed for
/// protocol v1 — a change is a new `sketch_format` tag, not a config knob.
pub const HLL_P: u8 = 12;

/// Number of registers (`1 << HLL_P`).
pub const HLL_REGISTERS: usize = 1 << HLL_P;

/// `sketch_format` tag for the only format defined today: a zstd frame
/// wrapping exactly `HLL_REGISTERS` raw register bytes.
const SKETCH_FORMAT_ZSTD_DENSE: u8 = 1;

/// zstd compression level for the dense register array (matches the snapshot
/// subsystem's choice).
const ZSTD_LEVEL: i32 = 3;

/// A fixed-size HyperLogLog register bank.
///
/// Cheap to clone (4 KiB). Stored behind a `Box` so it never lands on the
/// stack of a recursive gossip handler.
#[derive(Clone)]
pub struct Hll {
    registers: Box<[u8; HLL_REGISTERS]>,
}

impl Default for Hll {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Hll {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hll")
            .field("p", &HLL_P)
            .field("estimate", &self.estimate())
            .finish()
    }
}

impl Hll {
    /// A new, empty sketch (all registers zero → estimate 0).
    pub fn new() -> Self {
        Self {
            registers: Box::new([0u8; HLL_REGISTERS]),
        }
    }

    /// Record one `NewsPost` `msg_id`. Deterministic across nodes and node
    /// versions: the leading 64 bits of the (already uniform) digest select
    /// the register and the rank.
    pub fn insert(&mut self, msg_id: &[u8; 32]) {
        let h = u64::from_be_bytes([
            msg_id[0], msg_id[1], msg_id[2], msg_id[3], msg_id[4], msg_id[5], msg_id[6],
            msg_id[7],
        ]);
        // Top HLL_P bits pick the register.
        let idx = (h >> (64 - HLL_P as u32)) as usize;
        // Rank = 1 + number of leading zeros in the remaining bits. Shift the
        // index bits out, then OR a sentinel into the vacated low bits so
        // `leading_zeros()` is bounded by `64 - HLL_P` even for the (absurdly
        // unlikely) all-zero tail.
        let tail = (h << HLL_P as u32) | (1u64 << (HLL_P as u32 - 1));
        let rank = (tail.leading_zeros() as u8) + 1; // 1..=(64 - HLL_P + 1) = 1..=53
        if rank > self.registers[idx] {
            self.registers[idx] = rank;
        }
    }

    /// Fold `other` into `self` (set union of the two multisets).
    pub fn merge(&mut self, other: &Hll) {
        for i in 0..HLL_REGISTERS {
            if other.registers[i] > self.registers[i] {
                self.registers[i] = other.registers[i];
            }
        }
    }

    /// True if nothing has ever been inserted.
    #[allow(dead_code)] // used by tests + a natural part of the API
    pub fn is_empty(&self) -> bool {
        self.registers.iter().all(|&r| r == 0)
    }

    /// Estimated number of distinct `msg_id`s inserted.
    ///
    /// Flajolet's HLL estimator with a linear-counting correction in the
    /// small-cardinality range (the regime Hot Topics actually operates in).
    /// The large-range `2^32` correction is intentionally omitted — a per-tag
    /// per-hour distinct-post count never approaches it.
    pub fn estimate(&self) -> f64 {
        let m = HLL_REGISTERS as f64;
        let alpha = 0.7213 / (1.0 + 1.079 / m); // m >= 128
        let mut sum = 0.0f64;
        let mut zeros = 0usize;
        for &r in self.registers.iter() {
            sum += 2f64.powi(-(r as i32));
            if r == 0 {
                zeros += 1;
            }
        }
        let raw = alpha * m * m / sum;
        if raw <= 2.5 * m && zeros > 0 {
            // Linear counting is far more accurate than raw HLL here.
            return m * (m / zeros as f64).ln();
        }
        raw
    }

    /// `estimate()` rounded and saturated into a `u32` for the wire.
    pub fn estimate_u32(&self) -> u32 {
        let e = self.estimate().round();
        if e <= 0.0 {
            0
        } else if e >= u32::MAX as f64 {
            u32::MAX
        } else {
            e as u32
        }
    }

    /// Serialize for a `HotTopicsDigest`: `[sketch_format] ++ zstd(registers)`.
    /// Typical output is tens of bytes to ~1 KiB; the theoretical maximum
    /// (incompressible registers) is just over `HLL_REGISTERS`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let compressed = zstd::stream::encode_all(&self.registers[..], ZSTD_LEVEL)
            .expect("zstd encode of a fixed 4 KiB buffer cannot fail");
        let mut out = Vec::with_capacity(1 + compressed.len());
        out.push(SKETCH_FORMAT_ZSTD_DENSE);
        out.extend_from_slice(&compressed);
        out
    }

    /// Inverse of [`to_bytes`]. Returns `None` for an unknown `sketch_format`
    /// tag (caller: skip this tag, keep processing the rest of the digest),
    /// for a truncated/oversized frame, or for a zstd stream that does not
    /// decode to exactly `HLL_REGISTERS` bytes. The decode is hard-bounded to
    /// `HLL_REGISTERS + 1` output bytes, so a zstd bomb cannot be used here.
    pub fn from_bytes(bytes: &[u8]) -> Option<Hll> {
        let (&tag, rest) = bytes.split_first()?;
        if tag != SKETCH_FORMAT_ZSTD_DENSE {
            return None;
        }
        let decoder = zstd::stream::Decoder::new(rest).ok()?;
        let mut buf = Vec::with_capacity(HLL_REGISTERS);
        decoder
            .take((HLL_REGISTERS + 1) as u64)
            .read_to_end(&mut buf)
            .ok()?;
        if buf.len() != HLL_REGISTERS {
            return None;
        }
        let mut registers = Box::new([0u8; HLL_REGISTERS]);
        registers.copy_from_slice(&buf);
        Some(Hll { registers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> [u8; 32] {
        // A realistic msg_id is a Keccak-256 digest — genuinely uniform, WITH
        // the hash collisions a real stream has. A cheap deterministic stand-in
        // with the same statistical character is SHA-256 of the counter (the
        // node already depends on `sha2`).
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"ogmara-hll-test");
        h.update(n.to_le_bytes());
        h.finalize().into()
    }

    #[test]
    fn empty_sketch_estimates_zero() {
        assert_eq!(Hll::new().estimate_u32(), 0);
        assert!(Hll::new().is_empty());
    }

    #[test]
    fn estimate_is_within_error_bounds() {
        for &n in &[10u64, 100, 1_000, 10_000, 100_000] {
            let mut h = Hll::new();
            for i in 0..n {
                h.insert(&id(i));
            }
            let est = h.estimate();
            let err = (est - n as f64).abs() / n as f64;
            assert!(
                err < 0.05,
                "n={n} est={est:.0} rel_err={err:.4} exceeds 5%"
            );
        }
    }

    #[test]
    fn insert_is_idempotent() {
        let mut h = Hll::new();
        for _ in 0..50 {
            h.insert(&id(42));
        }
        assert_eq!(h.estimate_u32(), 1);
    }

    #[test]
    fn insert_is_order_independent() {
        let mut a = Hll::new();
        let mut b = Hll::new();
        for i in 0..2_000 {
            a.insert(&id(i));
        }
        for i in (0..2_000).rev() {
            b.insert(&id(i));
        }
        assert_eq!(a.registers, b.registers);
    }

    #[test]
    fn merge_of_overlapping_sets_counts_the_union_once() {
        // A = {0..1500}, B = {1000..2500}. Union = {0..2500} = 2500 distinct.
        let mut a = Hll::new();
        for i in 0..1_500 {
            a.insert(&id(i));
        }
        let mut b = Hll::new();
        for i in 1_000..2_500 {
            b.insert(&id(i));
        }
        a.merge(&b);
        let est = a.estimate();
        let err = (est - 2_500.0).abs() / 2_500.0;
        assert!(err < 0.05, "merged est={est:.0} rel_err={err:.4}");
    }

    #[test]
    fn merge_matches_a_single_sketch_of_all_elements() {
        // The N-nodes-see-the-same-post scenario: 5 sketches each holding the
        // SAME 200 posts. Merged estimate must be ~200, not ~1000.
        let mut merged = Hll::new();
        for _node in 0..5 {
            let mut s = Hll::new();
            for i in 0..200 {
                s.insert(&id(i));
            }
            merged.merge(&s);
        }
        let est = merged.estimate();
        assert!(
            (est - 200.0).abs() / 200.0 < 0.05,
            "over-counted: est={est:.0} (expected ~200)"
        );
    }

    #[test]
    fn merge_is_commutative_and_idempotent() {
        let mut a = Hll::new();
        for i in 0..800 {
            a.insert(&id(i));
        }
        let mut b = Hll::new();
        for i in 600..1_400 {
            b.insert(&id(i));
        }

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        assert_eq!(ab.registers, ba.registers, "merge not commutative");

        let mut ab_again = ab.clone();
        ab_again.merge(&b);
        ab_again.merge(&a);
        assert_eq!(ab.registers, ab_again.registers, "merge not idempotent");
    }

    #[test]
    fn roundtrips_through_the_wire_form() {
        let mut h = Hll::new();
        for i in 0..3_333 {
            h.insert(&id(i));
        }
        let bytes = h.to_bytes();
        assert!(
            bytes.len() <= HLL_REGISTERS + 16,
            "wire form unexpectedly large: {}",
            bytes.len()
        );
        let back = Hll::from_bytes(&bytes).expect("decode");
        assert_eq!(h.registers, back.registers);
    }

    #[test]
    fn empty_sketch_wire_form_is_tiny() {
        let bytes = Hll::new().to_bytes();
        assert!(bytes.len() < 64, "empty sketch encoded to {} bytes", bytes.len());
        let back = Hll::from_bytes(&bytes).expect("decode");
        assert!(back.is_empty());
    }

    #[test]
    fn unknown_sketch_format_is_rejected() {
        assert!(Hll::from_bytes(&[]).is_none());
        assert!(Hll::from_bytes(&[7, 1, 2, 3]).is_none());
    }

    #[test]
    fn truncated_frame_is_rejected() {
        let mut h = Hll::new();
        h.insert(&id(1));
        let mut bytes = h.to_bytes();
        bytes.truncate(bytes.len() / 2);
        assert!(Hll::from_bytes(&bytes).is_none());
    }
}
