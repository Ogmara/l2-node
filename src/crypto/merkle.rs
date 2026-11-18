//! Merkle tree for L2 state anchoring.
//!
//! Constructs a Merkle tree from the anchored state — the node's mirror of
//! what the chain says (`storage::anchored_state`) — generates state roots
//! for on-chain anchoring, and builds/verifies record inclusion proofs
//! against them. Uses SHA-256 hashing (spec 02-onchain.md section 7).
//! Nothing gossip-derived is anchored (messages, profiles, channel metadata,
//! memberships): nodes legitimately hold different sets of it, so a
//! commitment to it would stop anchorers from ever agreeing; those records
//! are authenticated by their authors' signatures instead.
//!
//! Tree structure (v4):
//!   State Root
//!   ├── Users Subtree        (on-chain registrations)
//!   ├── Channels Subtree     (on-chain channels)
//!   └── Delegations Subtree  (on-chain device delegations)

use sha2::{Digest, Sha256};

/// Compute SHA-256 hash of data.
#[cfg(test)]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Domain separator for internal nodes (prevents leaf-node confusion).
const INTERNAL_PREFIX: u8 = 0x01;
/// Domain separator for leaf nodes.
const LEAF_PREFIX: u8 = 0x00;
/// Domain constant framing the state-root hash (audit W14 / C2). The
/// suffix marks the canonical-root format generation; bump it on any
/// future change to the root construction:
///   - v1 → v2 (2026-06-07, W14): leaf-count framing added (defeats the
///     duplicate-last-node CVE-2012-2459 shape).
///   - v2 → v3 (2026-08-17, C2): added the channel-members subtree —
///     CHANNEL_MEMBERS was transferred by snapshot bootstrap but not
///     covered by the anchored commitment, letting a Sybil quorum inject
///     arbitrary private-channel membership grants into a fresh node.
///   - v3 → v4 (2026-11-17, l2-node 0.148.0): chain-only. The root covers
///     the scanner-owned chain mirror (users, channels, delegations) with
///     fixed canonical leaves; gossip-derived state (profiles, channel
///     metadata, members) left the root, and snapshots no longer import it.
///     v3 roots were never reproducible across nodes, so none ever became
///     canonical.
const STATE_ROOT_DOMAIN: &[u8] = b"ogmara-state-root-v4";

/// Hash two child nodes together: SHA-256(0x01 || left || right).
/// The 0x01 prefix distinguishes internal nodes from leaf hashes,
/// preventing second-preimage attacks.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([INTERNAL_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Hash a leaf value: SHA-256(0x00 || data).
/// The 0x00 prefix distinguishes leaves from internal nodes.
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash a (key, value) pair for snapshot Merkle trees.
///
/// Encodes `u32_be(key.len) || key || u32_be(value.len) || value` and feeds
/// it through `hash_leaf`. Both key length and value length are explicit so
/// `("a", "bc")` and `("ab", "c")` cannot collide.
///
/// Used by `Storage::build_snapshot_cf` to compute per-CF Merkle roots
/// (spec 11-snapshot-sync.md §3).
///
/// **Bounds:** RocksDB keys and values in Ogmara are always well under 4 GiB
/// (the largest realistic value is a few KB of MessagePack-encoded user
/// metadata). The current `MAX_BUILD_BYTES_PER_CF` cap (256 MiB) catches
/// adversarial single-row gigantism earlier in the pipeline. This function
/// asserts the u32 length encoding is safe rather than silently truncating.
///
/// # Panics
///
/// Panics if `key.len()` or `value.len()` exceeds `u32::MAX`. Reaching this
/// path implies a corrupted RocksDB read or a hostile-data ingress that should
/// already have been rejected earlier — a panic here is preferable to a
/// silent length-prefix truncation that would weaken second-preimage
/// resistance.
pub fn hash_kv(key: &[u8], value: &[u8]) -> [u8; 32] {
    let key_len = u32::try_from(key.len())
        .expect("hash_kv: key >= 4 GiB — refuse to encode (would truncate length prefix)");
    let value_len = u32::try_from(value.len())
        .expect("hash_kv: value >= 4 GiB — refuse to encode (would truncate length prefix)");
    let mut buf = Vec::with_capacity(8 + key.len() + value.len());
    buf.extend_from_slice(&key_len.to_be_bytes());
    buf.extend_from_slice(key);
    buf.extend_from_slice(&value_len.to_be_bytes());
    buf.extend_from_slice(value);
    hash_leaf(&buf)
}

/// Build a Merkle tree from a list of leaf hashes.
///
/// Returns the root hash. If the list is empty, returns a zero hash.
/// If the list has odd length, the last element is paired with itself.
pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);

        for chunk in current_level.chunks(2) {
            let left = &chunk[0];
            let right = if chunk.len() > 1 {
                &chunk[1]
            } else {
                left // duplicate last element for odd-length levels
            };
            next_level.push(hash_pair(left, right));
        }

        current_level = next_level;
    }

    current_level[0]
}

/// Every level of the tree [`compute_root`] builds, leaves first and the
/// root last. Built once per checkpoint subtree so inclusion paths can be
/// read off in O(log n) instead of rehashing the subtree per request.
/// Empty input yields no levels.
pub fn tree_levels(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    if leaves.is_empty() {
        return Vec::new();
    }
    let mut levels = vec![leaves.to_vec()];
    while levels.last().map_or(0, Vec::len) > 1 {
        let level = levels.last().expect("non-empty");
        let next = level
            .chunks(2)
            .map(|c| hash_pair(&c[0], c.get(1).unwrap_or(&c[0])))
            .collect();
        levels.push(next);
    }
    levels
}

/// Sibling hashes from leaf `index` up to the root of the tree in `levels`.
/// A node that is the odd last one on its level is paired with itself by
/// [`compute_root`], so it contributes no sibling entry — the verifier
/// derives that case from `index` and the leaf count.
pub fn inclusion_path(levels: &[Vec<[u8; 32]>], index: usize) -> Option<Vec<[u8; 32]>> {
    if index >= levels.first()?.len() {
        return None;
    }
    let mut path = Vec::new();
    let mut idx = index;
    for level in &levels[..levels.len() - 1] {
        let sibling = idx ^ 1;
        if sibling < level.len() {
            path.push(level[sibling]);
        }
        idx /= 2;
    }
    Some(path)
}

/// Recompute a subtree root from a leaf, its `index`, the subtree's
/// `leaf_count` and the sibling path from [`inclusion_path`]. Directions
/// come from the index, not from the proof, so a path cannot be replayed
/// at a different position. Returns `None` on a malformed proof (index out
/// of range, too few or too many siblings).
///
/// The node only builds proofs; this is the reference verifier its tests
/// check them with. Clients verify with sdk-js `verifyStateProof`, which
/// implements the same algorithm.
#[cfg(test)]
pub fn root_from_path(
    leaf: [u8; 32],
    index: u64,
    leaf_count: u64,
    siblings: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if index >= leaf_count {
        return None;
    }
    let mut hash = leaf;
    let mut idx = index;
    let mut n = leaf_count;
    let mut sibs = siblings.iter();
    while n > 1 {
        hash = if idx % 2 == 1 {
            hash_pair(sibs.next()?, &hash)
        } else if idx + 1 < n {
            hash_pair(&hash, sibs.next()?)
        } else {
            hash_pair(&hash, &hash)
        };
        idx /= 2;
        n = n.div_ceil(2);
    }
    if sibs.next().is_some() {
        return None;
    }
    Some(hash)
}

/// Number of anchored subtrees (users, channels, delegations).
pub const SUBTREE_COUNT: usize = 3;

/// Frame the subtree `(leaf_count, root)` pairs — users, channels,
/// delegations, in that order — into the anchored state root. The single
/// definition used by [`StateManager::compute_state_root`] and by
/// state-proof verification.
pub fn frame_state_root(subtrees: &[(u64, [u8; 32]); SUBTREE_COUNT]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STATE_ROOT_DOMAIN);
    for (count, root) in subtrees {
        hasher.update(count.to_be_bytes());
        hasher.update(root);
    }
    hasher.finalize().into()
}

/// The state manager that builds the anchored state Merkle tree from the
/// canonical leaf values of the three subtrees. Every leaf is
/// `hash_leaf(value)`: each canonical value re-encodes its own identifying
/// fields (address, channel id, user + device key), so the value alone
/// binds the record's identity.
pub struct StateManager {
    /// Leaf hashes per subtree, in [`frame_state_root`] order.
    leaves: [Vec<[u8; 32]>; SUBTREE_COUNT],
}

impl StateManager {
    pub fn new() -> Self {
        Self { leaves: Default::default() }
    }

    /// Add a leaf to subtree `index` (0 users, 1 channels, 2 delegations).
    ///
    /// Leaves go through `hash_leaf` (0x00 domain prefix) so they can never be
    /// confused with an internal node (0x01) — second-preimage resistance
    /// (audit 2026-06-07 W13).
    pub fn add(&mut self, index: usize, value: &[u8]) {
        self.leaves[index].push(hash_leaf(value));
    }

    /// Compute the state root from all subtrees.
    ///
    /// v2 (audit 2026-06-07 W14): the concatenation is framed with a domain
    /// constant and each subtree's leaf COUNT is mixed in, so the
    /// duplicate-last-node padding in `compute_root` (CVE-2012-2459 shape — a
    /// `[a,b,c]` tree and a `[a,b,c,c]` tree share a subtree root) can no longer
    /// forge the same *anchored* state root: the two differ by leaf count.
    ///
    /// **Canonical cross-node value — changing this changes every node's
    /// anchored root.** All anchoring nodes must run a build with the same
    /// `STATE_ROOT_DOMAIN` (v4: l2-node ≥0.148.0); a mixed fleet diverges.
    pub fn compute_state_root(&self) -> [u8; 32] {
        frame_state_root(&std::array::from_fn(|i| {
            (self.leaves[i].len() as u64, compute_root(&self.leaves[i]))
        }))
    }

    /// The leaf hashes of the subtrees, in [`frame_state_root`] order.
    #[cfg(test)]
    pub fn subtree_leaves(&self) -> &[Vec<[u8; 32]>; SUBTREE_COUNT] {
        &self.leaves
    }

    /// The state root and the subtrees' leaves, moved out (no copy).
    pub fn into_root_and_leaves(self) -> ([u8; 32], [Vec<[u8; 32]>; SUBTREE_COUNT]) {
        let root = self.compute_state_root();
        (root, self.leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_root() {
        assert_eq!(compute_root(&[]), [0u8; 32]);
    }

    #[test]
    fn test_single_leaf() {
        let leaf = sha256(b"hello");
        assert_eq!(compute_root(&[leaf]), leaf);
    }

    #[test]
    fn test_two_leaves() {
        let a = sha256(b"alice");
        let b = sha256(b"bob");
        let root = compute_root(&[a, b]);
        assert_eq!(root, hash_pair(&a, &b));
    }

    #[test]
    fn test_three_leaves_odd() {
        let a = sha256(b"one");
        let b = sha256(b"two");
        let c = sha256(b"three");
        let root = compute_root(&[a, b, c]);

        // c is duplicated for odd-length: level1 = [H(a,b), H(c,c)]
        let ab = hash_pair(&a, &b);
        let cc = hash_pair(&c, &c);
        let expected = hash_pair(&ab, &cc);
        assert_eq!(root, expected);
    }

    #[test]
    fn inclusion_paths_rebuild_the_root_for_every_leaf_and_size() {
        for n in 1..=33u64 {
            let leaves: Vec<[u8; 32]> = (0..n).map(|i| sha256(&i.to_be_bytes())).collect();
            let root = compute_root(&leaves);
            let levels = tree_levels(&leaves);
            assert_eq!(levels.last().unwrap()[0], root, "n={n}");
            for i in 0..n {
                let path = inclusion_path(&levels, i as usize).unwrap();
                assert_eq!(
                    root_from_path(leaves[i as usize], i, n, &path),
                    Some(root),
                    "n={n} i={i}"
                );
            }
        }
    }

    #[test]
    fn tampered_or_misplaced_proofs_fail() {
        let leaves: Vec<[u8; 32]> = (0..7u8).map(|i| sha256(&[i])).collect();
        let root = compute_root(&leaves);
        let levels = tree_levels(&leaves);
        let path = inclusion_path(&levels, 2).unwrap();
        // Wrong leaf.
        assert_ne!(root_from_path(sha256(b"x"), 2, 7, &path), Some(root));
        // Same path claimed at another index.
        assert_ne!(root_from_path(leaves[2], 3, 7, &path), Some(root));
        // A different leaf count can rebuild the same SUBTREE root for an
        // interior leaf (the duplicate-last-node shape); counts are bound
        // one level up, by `frame_state_root`, which hashes each count in.
        // Index out of range, extra or missing siblings.
        assert_eq!(root_from_path(leaves[2], 7, 7, &path), None);
        let mut longer = path.clone();
        longer.push([0u8; 32]);
        assert_eq!(root_from_path(leaves[2], 2, 7, &longer), None);
        assert_eq!(root_from_path(leaves[2], 2, 7, &path[..path.len() - 1]), None);
        assert_eq!(inclusion_path(&levels, 7), None);
    }

    #[test]
    fn frame_state_root_matches_state_manager() {
        let mut sm = StateManager::new();
        sm.add(0, b"u1");
        sm.add(0, b"u2");
        sm.add(1, b"c1");
        let [u, c, d] = sm.subtree_leaves();
        let framed = frame_state_root(&[
            (u.len() as u64, compute_root(u)),
            (c.len() as u64, compute_root(c)),
            (d.len() as u64, compute_root(d)),
        ]);
        assert_eq!(framed, sm.compute_state_root());
    }

    #[test]
    fn every_subtree_participates_and_position_matters() {
        let mut base = StateManager::new();
        base.add(0, b"x");
        for i in 0..SUBTREE_COUNT {
            let mut other = StateManager::new();
            other.add(0, b"x");
            other.add(i, b"y");
            assert_ne!(base.compute_state_root(), other.compute_state_root(), "subtree {i}");
        }
        // The same leaf in a different subtree is a different root.
        let mut a = StateManager::new();
        a.add(1, b"z");
        let mut b = StateManager::new();
        b.add(2, b"z");
        assert_ne!(a.compute_state_root(), b.compute_state_root());
    }

    #[test]
    fn state_manager_uses_leaf_domain_separation() {
        // W13: StateManager leaves must be hash_leaf (0x00), not bare sha256.
        let mut sm = StateManager::new();
        sm.add(0, b"u");
        // Single-leaf subtree root == the leaf == hash_leaf(data), NOT sha256.
        assert_eq!(compute_root(&sm.leaves[0]), hash_leaf(b"u"));
        assert_ne!(compute_root(&sm.leaves[0]), sha256(b"u"));
    }

    #[test]
    fn state_root_leaf_count_framing_defeats_duplicate_last() {
        // W14 / CVE-2012-2459: a subtree of [a,b,c] and [a,b,c,c] share the same
        // `compute_root`, but the leaf-count framing must make the *state roots*
        // differ so a padded duplicate can't forge the anchored root.
        let mut a = StateManager::new();
        for v in [b"a", b"b", b"c"] {
            a.add(0, v);
        }
        let mut b = StateManager::new();
        for v in [b"a", b"b", b"c", b"c"] {
            b.add(0, v);
        }
        assert_eq!(
            compute_root(&a.leaves[0]),
            compute_root(&b.leaves[0]),
            "precondition: duplicate-last shares the bare subtree root",
        );
        assert_ne!(
            a.compute_state_root(),
            b.compute_state_root(),
            "leaf-count framing must distinguish the two anchored roots",
        );
    }
}
