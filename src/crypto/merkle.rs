//! Merkle tree for L2 state anchoring.
//!
//! Constructs a Merkle tree from L2 state (users, channel metadata,
//! delegations, channel members), generates state roots for on-chain
//! anchoring, and builds/verifies record inclusion proofs against them.
//! Uses SHA-256 hashing (spec 02-onchain.md section 7). Messages are not
//! part of the anchored state: nodes legitimately hold different message
//! sets, so a message commitment would stop anchorers from agreeing.
//!
//! Tree structure:
//!   State Root
//!   ├── Users Subtree
//!   ├── Channels Subtree (channel metadata records)
//!   ├── Delegations Subtree
//!   └── Channel Members Subtree (added v3, audit final pre-mainnet C2)

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
const STATE_ROOT_DOMAIN: &[u8] = b"ogmara-state-root-v3";

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

/// Frame the four subtree `(leaf_count, root)` pairs — users, channels,
/// delegations, channel members, in that order — into the anchored state
/// root. The single definition used by [`StateManager::compute_state_root`]
/// and by state-proof verification.
pub fn frame_state_root(subtrees: &[(u64, [u8; 32]); 4]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STATE_ROOT_DOMAIN);
    for (count, root) in subtrees {
        hasher.update(count.to_be_bytes());
        hasher.update(root);
    }
    hasher.finalize().into()
}

/// The state manager that builds and maintains the L2 state Merkle tree.
///
/// Composed of four subtrees: users, channels (metadata only — messages
/// are not part of the anchored state, see spec 02 §7), delegations,
/// channel members.
pub struct StateManager {
    /// Hashes of user states.
    user_hashes: Vec<[u8; 32]>,
    /// Hashes of channel metadata records.
    channel_hashes: Vec<[u8; 32]>,
    /// Hashes of delegation records.
    delegation_hashes: Vec<[u8; 32]>,
    /// Hashes of channel-membership records (added v3, audit C2).
    channel_member_hashes: Vec<[u8; 32]>,
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            user_hashes: Vec::new(),
            channel_hashes: Vec::new(),
            delegation_hashes: Vec::new(),
            channel_member_hashes: Vec::new(),
        }
    }

    /// Add a user state hash.
    ///
    /// Leaves go through `hash_leaf` (0x00 domain prefix) so they can never be
    /// confused with an internal node (0x01) — second-preimage resistance
    /// (audit 2026-06-07 W13). Previously these used bare `sha256`, bypassing
    /// the domain separation that `hash_pair` relies on.
    pub fn add_user(&mut self, user_data: &[u8]) {
        self.user_hashes.push(hash_leaf(user_data));
    }

    /// Add a channel metadata record hash.
    pub fn add_channel(&mut self, channel_data: &[u8]) {
        self.channel_hashes.push(hash_leaf(channel_data));
    }

    /// Add a delegation record hash.
    pub fn add_delegation(&mut self, delegation_data: &[u8]) {
        self.delegation_hashes.push(hash_leaf(delegation_data));
    }

    /// Add a channel-membership record hash (v3, audit final pre-mainnet
    /// C2). `CHANNEL_MEMBERS` is transferred by snapshot bootstrap like the
    /// other three CFs, but was not covered by the anchored commitment
    /// until this subtree was added — a Sybil quorum could inject arbitrary
    /// private-channel membership grants into a fresh bootstrapping node.
    ///
    /// **Unlike `add_user`/`add_channel`/`add_delegation`, this hashes the
    /// KEY together with the value (`hash_kv`, not bare `hash_leaf`).** The
    /// other three CFs' values happen to redundantly re-encode their own
    /// identifying key fields (e.g. a USERS value includes `"address"`), so
    /// hashing the value alone still binds identity. `CHANNEL_MEMBERS`
    /// values do NOT — the production write path
    /// (`MessageRouter::add_channel_member`, router.rs) stores only
    /// `{"joined_at": ..., "role": ...}`; `channel_id` and the member's
    /// address live ONLY in the key (`encode_channel_member_key`). Hashing
    /// the value alone would let an attacker reassign genuine
    /// `(joined_at, role)` values to a completely different
    /// `(channel_id, address)` key — same leaf multiset, same root, but
    /// arbitrary membership grants. `hash_kv` (already used for per-CF
    /// snapshot integrity in `Storage::build_snapshot_cf`) binds both.
    pub fn add_channel_member(&mut self, key: &[u8], value: &[u8]) {
        self.channel_member_hashes.push(hash_kv(key, value));
    }

    /// Compute the state root from all four subtrees.
    ///
    /// v2 (audit 2026-06-07 W14): the concatenation is framed with a domain
    /// constant and each subtree's leaf COUNT is mixed in, so the
    /// duplicate-last-node padding in `compute_root` (CVE-2012-2459 shape — a
    /// `[a,b,c]` tree and a `[a,b,c,c]` tree share a subtree root) can no longer
    /// forge the same *anchored* state root: the two differ by leaf count.
    /// v3 (audit C2, 2026-08-17): added the channel-members subtree,
    /// following the exact same framing.
    ///
    /// **Canonical cross-node value — changing this changes every node's
    /// anchored root.** All anchoring nodes must run a build with the same
    /// `STATE_ROOT_DOMAIN` (v2: l2-node ≥0.62.0; v3: l2-node ≥0.86.0); a
    /// mixed fleet would diverge.
    pub fn compute_state_root(&self) -> [u8; 32] {
        let users_root = compute_root(&self.user_hashes);
        let channels_root = compute_root(&self.channel_hashes);
        let delegations_root = compute_root(&self.delegation_hashes);
        let channel_members_root = compute_root(&self.channel_member_hashes);

        frame_state_root(&[
            (self.user_hashes.len() as u64, users_root),
            (self.channel_hashes.len() as u64, channels_root),
            (self.delegation_hashes.len() as u64, delegations_root),
            (self.channel_member_hashes.len() as u64, channel_members_root),
        ])
    }

    /// The leaf hashes of the four subtrees, in [`frame_state_root`] order
    /// — exactly what [`Self::compute_state_root`] hashed, so a state
    /// checkpoint stores the same leaves the anchored root commits to.
    #[cfg(test)]
    pub fn subtree_leaves(&self) -> [&[[u8; 32]]; 4] {
        [
            &self.user_hashes,
            &self.channel_hashes,
            &self.delegation_hashes,
            &self.channel_member_hashes,
        ]
    }

    /// The state root and the four subtrees' leaves, moved out (no copy).
    pub fn into_root_and_leaves(self) -> ([u8; 32], [Vec<[u8; 32]>; 4]) {
        let root = self.compute_state_root();
        (
            root,
            [
                self.user_hashes,
                self.channel_hashes,
                self.delegation_hashes,
                self.channel_member_hashes,
            ],
        )
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
        sm.add_user(b"u1");
        sm.add_user(b"u2");
        sm.add_channel(b"c1");
        sm.add_channel_member(b"k", b"v");
        let [u, c, d, m] = sm.subtree_leaves();
        let framed = frame_state_root(&[
            (u.len() as u64, compute_root(u)),
            (c.len() as u64, compute_root(c)),
            (d.len() as u64, compute_root(d)),
            (m.len() as u64, compute_root(m)),
        ]);
        assert_eq!(framed, sm.compute_state_root());
    }

    #[test]
    fn test_state_manager() {
        let mut sm = StateManager::new();
        sm.add_user(b"user1");
        sm.add_user(b"user2");
        sm.add_channel(b"channel1");
        sm.add_delegation(b"delegation1");

        let root = sm.compute_state_root();
        assert_ne!(root, [0u8; 32]);

        // Same data should produce the same root
        let root2 = sm.compute_state_root();
        assert_eq!(root, root2);
    }

    #[test]
    fn channel_member_participates_in_state_root() {
        // C2: the channel-members subtree must actually affect the anchored
        // root — otherwise adding it is a no-op and the fix does nothing.
        let mut without_member = StateManager::new();
        without_member.add_user(b"user1");
        without_member.add_channel(b"channel1");
        without_member.add_delegation(b"delegation1");

        let mut with_member = StateManager::new();
        with_member.add_user(b"user1");
        with_member.add_channel(b"channel1");
        with_member.add_delegation(b"delegation1");
        with_member.add_channel_member(b"key1", b"member1");

        assert_ne!(without_member.compute_state_root(), with_member.compute_state_root());
    }

    #[test]
    fn channel_member_binds_key_not_just_value() {
        // Regression: CHANNEL_MEMBERS values don't redundantly encode their
        // key (channel_id + address) the way USERS/DELEGATIONS values do —
        // production rows are just {"joined_at": ..., "role": ...}. If the
        // leaf hash only covered the value, an attacker could reassign a
        // genuine (joined_at, role) blob to a totally different
        // (channel_id, address) key and produce the SAME root — same
        // multiset of values, different (and forged) membership grants.
        let mut a = StateManager::new();
        a.add_channel_member(b"channel1:klv1alice", b"{\"joined_at\":1,\"role\":\"member\"}");

        let mut b = StateManager::new();
        // Same VALUE, different KEY — must NOT produce the same root.
        b.add_channel_member(b"channel2:klv1mallory", b"{\"joined_at\":1,\"role\":\"member\"}");

        assert_ne!(a.compute_state_root(), b.compute_state_root());
    }

    #[test]
    fn state_manager_uses_leaf_domain_separation() {
        // W13: StateManager leaves must be hash_leaf (0x00), not bare sha256.
        let mut sm = StateManager::new();
        sm.add_user(b"u");
        // Single-leaf subtree root == the leaf == hash_leaf(data), NOT sha256.
        assert_eq!(compute_root(&sm.user_hashes), hash_leaf(b"u"));
        assert_ne!(compute_root(&sm.user_hashes), sha256(b"u"));
    }

    #[test]
    fn state_root_leaf_count_framing_defeats_duplicate_last() {
        // W14 / CVE-2012-2459: a subtree of [a,b,c] and [a,b,c,c] share the same
        // `compute_root`, but the leaf-count framing must make the *state roots*
        // differ so a padded duplicate can't forge the anchored root.
        let mut a = StateManager::new();
        a.add_user(b"a");
        a.add_user(b"b");
        a.add_user(b"c");

        let mut b = StateManager::new();
        b.add_user(b"a");
        b.add_user(b"b");
        b.add_user(b"c");
        b.add_user(b"c"); // duplicated last → same compute_root, different count

        assert_eq!(
            compute_root(&a.user_hashes),
            compute_root(&b.user_hashes),
            "precondition: duplicate-last shares the bare subtree root",
        );
        assert_ne!(
            a.compute_state_root(),
            b.compute_state_root(),
            "leaf-count framing must distinguish the two anchored roots",
        );
    }
}
