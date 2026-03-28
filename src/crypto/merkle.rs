//! Sparse Merkle tree for L2 state anchoring.
//!
//! Constructs a Merkle tree from L2 state (users, channels, messages,
//! delegations) and generates state roots for on-chain anchoring.
//! Uses SHA-256 hashing (spec 02-onchain.md section 7).
//!
//! Tree structure:
//!   State Root
//!   ├── Users Subtree
//!   ├── Channels Subtree (each channel has metadata + messages subtree)
//!   └── Delegations Subtree

use sha2::{Digest, Sha256};

/// A node in the Merkle tree.
#[derive(Debug, Clone)]
enum MerkleNode {
    /// Leaf node containing a SHA-256 hash of data.
    Leaf([u8; 32]),
    /// Internal node with left and right children.
    Internal {
        hash: [u8; 32],
        left: Box<MerkleNode>,
        right: Box<MerkleNode>,
    },
    /// Empty placeholder for sparse tree positions.
    Empty,
}

impl MerkleNode {
    fn hash(&self) -> [u8; 32] {
        match self {
            MerkleNode::Leaf(h) => *h,
            MerkleNode::Internal { hash, .. } => *hash,
            MerkleNode::Empty => [0u8; 32],
        }
    }
}

/// A Merkle proof path for verifying inclusion of a leaf.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Leaf hash being proven.
    pub leaf_hash: [u8; 32],
    /// Sibling hashes from leaf to root, with position (true = left sibling).
    pub path: Vec<(bool, [u8; 32])>,
    /// Expected root hash.
    pub root: [u8; 32],
}

impl MerkleProof {
    /// Verify the proof by recomputing the root from the leaf.
    pub fn verify(&self) -> bool {
        let mut current = self.leaf_hash;

        for (is_left, sibling) in &self.path {
            current = if *is_left {
                hash_pair(sibling, &current)
            } else {
                hash_pair(&current, sibling)
            };
        }

        current == self.root
    }
}

/// Compute SHA-256 hash of data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Domain separator for internal nodes (prevents leaf-node confusion).
const INTERNAL_PREFIX: u8 = 0x01;
/// Domain separator for leaf nodes.
const LEAF_PREFIX: u8 = 0x00;

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

/// Build a Merkle proof for a leaf at the given index.
///
/// Returns None if the index is out of range.
pub fn build_proof(leaves: &[[u8; 32]], index: usize) -> Option<MerkleProof> {
    if index >= leaves.len() || leaves.is_empty() {
        return None;
    }

    let root = compute_root(leaves);
    let mut path = Vec::new();
    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();
    let mut current_index = index;

    while current_level.len() > 1 {
        // Pad to even length
        if current_level.len() % 2 != 0 {
            let last = *current_level.last().unwrap();
            current_level.push(last);
        }

        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };

        let is_left = current_index % 2 != 0; // sibling is on the left
        path.push((is_left, current_level[sibling_index]));

        // Build next level
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for chunk in current_level.chunks(2) {
            next_level.push(hash_pair(&chunk[0], &chunk[1]));
        }

        current_level = next_level;
        current_index /= 2;
    }

    Some(MerkleProof {
        leaf_hash: leaves[index],
        path,
        root,
    })
}

/// The state manager that builds and maintains the L2 state Merkle tree.
///
/// Composed of three subtrees: users, channels (with messages), delegations.
pub struct StateManager {
    /// Hashes of user states.
    user_hashes: Vec<[u8; 32]>,
    /// Hashes of channel states (metadata + message subtree roots).
    channel_hashes: Vec<[u8; 32]>,
    /// Hashes of delegation records.
    delegation_hashes: Vec<[u8; 32]>,
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            user_hashes: Vec::new(),
            channel_hashes: Vec::new(),
            delegation_hashes: Vec::new(),
        }
    }

    /// Add a user state hash.
    pub fn add_user(&mut self, user_data: &[u8]) {
        self.user_hashes.push(sha256(user_data));
    }

    /// Add a channel state hash (metadata + message subtree root).
    pub fn add_channel(&mut self, channel_data: &[u8]) {
        self.channel_hashes.push(sha256(channel_data));
    }

    /// Add a delegation record hash.
    pub fn add_delegation(&mut self, delegation_data: &[u8]) {
        self.delegation_hashes.push(sha256(delegation_data));
    }

    /// Compute the state root from all three subtrees.
    ///
    /// State Root = SHA-256(users_root || channels_root || delegations_root)
    pub fn compute_state_root(&self) -> [u8; 32] {
        let users_root = compute_root(&self.user_hashes);
        let channels_root = compute_root(&self.channel_hashes);
        let delegations_root = compute_root(&self.delegation_hashes);

        let mut hasher = Sha256::new();
        hasher.update(users_root);
        hasher.update(channels_root);
        hasher.update(delegations_root);
        hasher.finalize().into()
    }

    /// Get counts for the state anchor event.
    pub fn counts(&self) -> (u64, u32, u32) {
        // (message_count is tracked separately, not in hashes)
        (0, self.channel_hashes.len() as u32, self.user_hashes.len() as u32)
    }

    /// Reset the state manager for a fresh computation.
    pub fn reset(&mut self) {
        self.user_hashes.clear();
        self.channel_hashes.clear();
        self.delegation_hashes.clear();
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
    fn test_proof_verify() {
        let leaves: Vec<[u8; 32]> = (0..8u8).map(|i| sha256(&[i])).collect();
        for i in 0..leaves.len() {
            let proof = build_proof(&leaves, i).unwrap();
            assert!(proof.verify(), "proof failed for leaf {}", i);
        }
    }

    #[test]
    fn test_proof_wrong_leaf_fails() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| sha256(&[i])).collect();
        let mut proof = build_proof(&leaves, 0).unwrap();
        proof.leaf_hash = sha256(b"tampered");
        assert!(!proof.verify());
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
}
