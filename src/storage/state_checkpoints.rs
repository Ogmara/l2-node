//! Anchored state checkpoints for record inclusion proofs (spec 03 §3.6,
//! l2-node 0.147.0+).
//!
//! When the `StateAnchorer` broadcasts an anchor it stores the exact leaves
//! the anchored root commits to: per subtree (users, channels, delegations,
//! channel members) the RocksDB keys in iteration order and their leaf
//! hashes. `GET /api/v1/state/proof` reads a record's position and sibling
//! path from here, so a client can rebuild the anchored root and compare it
//! with `getCanonicalAnchor` on-chain without trusting the node.
//!
//! Layout in `STATE_CHECKPOINTS` (node-local, not in snapshot `DOMAIN_CFS`):
//! - `b'h' ++ height_be8` → header: format byte, state root, then four
//!   `(leaf_count u64 BE, subtree_root[32])` pairs.
//! - `b's' ++ height_be8 ++ subtree_u8` → format byte, `u32 BE` entry
//!   count, then per entry `u16 BE key_len ++ key ++ leaf[32]`.
//! - `b'c' ++ height_be8` → empty: the anchorer's divergence watcher saw
//!   this height's FINAL canonical root on-chain equal ours. Proofs default
//!   to the newest such height, because a client can only verify against a
//!   canonical root.
//!
//! Headers live under their own prefix so listing heights never loads the
//! (potentially multi-MB) subtree blobs. The newest
//! [`MAX_STATE_CHECKPOINTS`] heights are kept, plus the newest
//! canonical-confirmed one when it is older (canonicalization can take
//! longer than a few anchor intervals).

use anyhow::{bail, Context, Result};
use rocksdb::WriteBatch;

use super::rocks::Storage;
use super::schema::cf;
use crate::crypto::merkle::{compute_root, hash_kv, hash_leaf};

/// Anchored heights kept. At the default 1 h anchor interval this covers
/// the window in which a height becomes canonical on-chain.
pub const MAX_STATE_CHECKPOINTS: usize = 4;

const HEADER_PREFIX: u8 = b'h';
const SUBTREE_PREFIX: u8 = b's';
const CANONICAL_PREFIX: u8 = b'c';
const FORMAT_V1: u8 = 1;
const HEADER_LEN: usize = 1 + 32 + 4 * (8 + 32);

/// One of the four anchored subtrees, in state-root framing order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subtree {
    Users = 0,
    Channels = 1,
    Delegations = 2,
    ChannelMembers = 3,
}

impl Subtree {
    pub const ALL: [Subtree; 4] = [
        Subtree::Users,
        Subtree::Channels,
        Subtree::Delegations,
        Subtree::ChannelMembers,
    ];

    /// Position in the state-root framing (and in checkpoint arrays).
    pub fn index(self) -> usize {
        self as usize
    }

    /// The column family whose rows are this subtree's leaves.
    pub fn cf(self) -> &'static str {
        match self {
            Subtree::Users => cf::USERS,
            Subtree::Channels => cf::CHANNELS,
            Subtree::Delegations => cf::DELEGATIONS,
            Subtree::ChannelMembers => cf::CHANNEL_MEMBERS,
        }
    }

    /// Wire name used by the proof API.
    pub fn name(self) -> &'static str {
        match self {
            Subtree::Users => "users",
            Subtree::Channels => "channels",
            Subtree::Delegations => "delegations",
            Subtree::ChannelMembers => "channel_members",
        }
    }

    /// Leaf hash of a row, exactly as `StateManager` computes it: the value
    /// alone for the first three (their values re-encode their own key
    /// fields), key and value together for channel members.
    pub fn leaf(self, key: &[u8], value: &[u8]) -> [u8; 32] {
        match self {
            Subtree::ChannelMembers => hash_kv(key, value),
            _ => hash_leaf(value),
        }
    }
}

/// The ordered keys and leaf hashes of one subtree at a checkpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubtreeCheckpoint {
    pub keys: Vec<Vec<u8>>,
    pub leaves: Vec<[u8; 32]>,
}

/// Everything the anchored root at one height commits to.
#[derive(Debug, Clone)]
pub struct StateCheckpoint {
    pub state_root: [u8; 32],
    pub subtrees: [SubtreeCheckpoint; 4],
}

/// The small per-height summary a proof needs besides the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointHeader {
    pub block_height: u64,
    pub state_root: [u8; 32],
    /// `(leaf_count, subtree_root)` in framing order.
    pub subtrees: [(u64, [u8; 32]); 4],
}

fn header_key(height: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(9);
    k.push(HEADER_PREFIX);
    k.extend_from_slice(&height.to_be_bytes());
    k
}

fn canonical_key(height: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(9);
    k.push(CANONICAL_PREFIX);
    k.extend_from_slice(&height.to_be_bytes());
    k
}

fn subtree_key(height: u64, subtree: Subtree) -> Vec<u8> {
    let mut k = Vec::with_capacity(10);
    k.push(SUBTREE_PREFIX);
    k.extend_from_slice(&height.to_be_bytes());
    k.push(subtree as u8);
    k
}

fn encode_header(cp: &StateCheckpoint) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.push(FORMAT_V1);
    out.extend_from_slice(&cp.state_root);
    for st in &cp.subtrees {
        out.extend_from_slice(&(st.leaves.len() as u64).to_be_bytes());
        out.extend_from_slice(&compute_root(&st.leaves));
    }
    out
}

fn decode_header(block_height: u64, raw: &[u8]) -> Result<CheckpointHeader> {
    if raw.len() != HEADER_LEN || raw[0] != FORMAT_V1 {
        bail!("state checkpoint header at height {block_height} has an unknown format");
    }
    let state_root: [u8; 32] = raw[1..33].try_into().expect("length checked");
    let mut subtrees = [(0u64, [0u8; 32]); 4];
    for (i, slot) in subtrees.iter_mut().enumerate() {
        let at = 33 + i * 40;
        let count = u64::from_be_bytes(raw[at..at + 8].try_into().expect("length checked"));
        let root: [u8; 32] = raw[at + 8..at + 40].try_into().expect("length checked");
        *slot = (count, root);
    }
    Ok(CheckpointHeader { block_height, state_root, subtrees })
}

fn encode_subtree(st: &SubtreeCheckpoint) -> Result<Vec<u8>> {
    let count = u32::try_from(st.keys.len()).context("state checkpoint subtree too large")?;
    let size: usize = st.keys.iter().map(|k| 2 + k.len() + 32).sum();
    let mut out = Vec::with_capacity(5 + size);
    out.push(FORMAT_V1);
    out.extend_from_slice(&count.to_be_bytes());
    for (key, leaf) in st.keys.iter().zip(&st.leaves) {
        let len = u16::try_from(key.len()).context("state checkpoint key longer than 64 KiB")?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(leaf);
    }
    Ok(out)
}

fn decode_subtree(raw: &[u8]) -> Result<SubtreeCheckpoint> {
    if raw.len() < 5 || raw[0] != FORMAT_V1 {
        bail!("state checkpoint subtree has an unknown format");
    }
    let count = u32::from_be_bytes(raw[1..5].try_into().expect("length checked")) as usize;
    // Each entry is at least 34 bytes; reject a count the blob can't hold
    // before reserving memory for it.
    if count > (raw.len() - 5) / 34 {
        bail!("state checkpoint subtree is truncated");
    }
    let mut keys = Vec::with_capacity(count);
    let mut leaves = Vec::with_capacity(count);
    let mut at = 5;
    for _ in 0..count {
        let len_end = at + 2;
        let len = u16::from_be_bytes(
            raw.get(at..len_end).context("truncated subtree entry")?.try_into()?,
        ) as usize;
        let key_end = len_end + len;
        let leaf_end = key_end + 32;
        keys.push(raw.get(len_end..key_end).context("truncated subtree key")?.to_vec());
        leaves.push(raw.get(key_end..leaf_end).context("truncated subtree leaf")?.try_into()?);
        at = leaf_end;
    }
    if at != raw.len() {
        bail!("state checkpoint subtree has trailing bytes");
    }
    Ok(SubtreeCheckpoint { keys, leaves })
}

impl Storage {
    /// Persist the checkpoint for an anchor broadcast at `block_height` and
    /// prune: keep the newest [`MAX_STATE_CHECKPOINTS`] heights plus the
    /// newest canonical-confirmed one. Header and subtrees go in one batch,
    /// so a header never exists without its data. Re-storing a height
    /// clears its canonical mark (the root may differ now).
    pub fn store_state_checkpoint(&self, block_height: u64, cp: &StateCheckpoint) -> Result<()> {
        let handle = self.cf_handle(cf::STATE_CHECKPOINTS)?;
        let mut batch = WriteBatch::default();
        batch.put_cf(&handle, header_key(block_height), encode_header(cp));
        batch.delete_cf(&handle, canonical_key(block_height));
        for subtree in Subtree::ALL {
            batch.put_cf(
                &handle,
                subtree_key(block_height, subtree),
                encode_subtree(&cp.subtrees[subtree.index()])?,
            );
        }
        let mut heights = self.state_checkpoint_heights()?;
        if !heights.contains(&block_height) {
            heights.push(block_height);
        }
        heights.sort_unstable_by(|a, b| b.cmp(a));
        let keep_canonical = self
            .canonical_state_checkpoint_heights()?
            .into_iter()
            .filter(|h| *h != block_height)
            .max();
        for old in heights.iter().skip(MAX_STATE_CHECKPOINTS) {
            if Some(*old) == keep_canonical {
                continue;
            }
            batch.delete_cf(&handle, header_key(*old));
            batch.delete_cf(&handle, canonical_key(*old));
            for subtree in Subtree::ALL {
                batch.delete_cf(&handle, subtree_key(*old, subtree));
            }
        }
        drop(handle);
        self.write_batch(batch).context("writing state checkpoint")
    }

    /// Record that `block_height`'s final canonical root on-chain equals the
    /// stored checkpoint's root. Ignored when no checkpoint (or a different
    /// root) is stored for that height.
    pub fn mark_state_checkpoint_canonical(&self, block_height: u64, root_hex: &str) -> Result<()> {
        match self.load_state_checkpoint_header(block_height)? {
            Some(h) if hex::encode(h.state_root).eq_ignore_ascii_case(root_hex) => {
                self.put_cf(cf::STATE_CHECKPOINTS, &canonical_key(block_height), &[])
            }
            _ => Ok(()),
        }
    }

    /// Heights whose checkpoint matched the final canonical root, ascending.
    pub fn canonical_state_checkpoint_heights(&self) -> Result<Vec<u64>> {
        let rows = self.prefix_iter_cf(
            cf::STATE_CHECKPOINTS,
            &[CANONICAL_PREFIX],
            (MAX_STATE_CHECKPOINTS + 1) * 4,
        )?;
        Ok(rows
            .iter()
            .filter_map(|(k, _)| Some(u64::from_be_bytes(k.get(1..9)?.try_into().ok()?)))
            .collect())
    }

    /// Heights that have a stored checkpoint, in ascending order.
    pub fn state_checkpoint_heights(&self) -> Result<Vec<u64>> {
        // Bounded by the retention cap; the slack only matters if a crash
        // ever left extra rows behind, and the next store prunes them.
        let rows = self.prefix_iter_cf(
            cf::STATE_CHECKPOINTS,
            &[HEADER_PREFIX],
            MAX_STATE_CHECKPOINTS * 4,
        )?;
        Ok(rows
            .iter()
            .filter_map(|(k, _)| Some(u64::from_be_bytes(k.get(1..9)?.try_into().ok()?)))
            .collect())
    }

    /// Header of the checkpoint at `block_height`, if one is stored.
    pub fn load_state_checkpoint_header(&self, block_height: u64) -> Result<Option<CheckpointHeader>> {
        self.get_cf(cf::STATE_CHECKPOINTS, &header_key(block_height))?
            .map(|raw| decode_header(block_height, &raw))
            .transpose()
    }

    /// Keys and leaves of one subtree of the checkpoint at `block_height`.
    pub fn load_state_checkpoint_subtree(
        &self,
        block_height: u64,
        subtree: Subtree,
    ) -> Result<Option<SubtreeCheckpoint>> {
        self.get_cf(cf::STATE_CHECKPOINTS, &subtree_key(block_height, subtree))?
            .map(|raw| decode_subtree(&raw))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::merkle::frame_state_root;

    fn open() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    #[test]
    fn checkpoint_matches_the_anchored_root_and_round_trips() {
        let (s, _d) = open();
        s.put_cf(cf::USERS, b"klv1alice", br#"{"address":"klv1alice"}"#).unwrap();
        s.put_cf(cf::USERS, b"klv1bob", br#"{"address":"klv1bob"}"#).unwrap();
        s.put_cf(cf::CHANNELS, &7u64.to_be_bytes(), br#"{"channel_id":7}"#).unwrap();
        s.put_cf(
            cf::CHANNEL_MEMBERS,
            &crate::storage::schema::encode_channel_member_key(7, "klv1alice"),
            br#"{"role":"member"}"#,
        )
        .unwrap();

        let cp = s.compute_state_checkpoint().unwrap();
        let (root, ..) = s.compute_current_state_root().unwrap();
        assert_eq!(cp.state_root, root);
        assert_eq!(cp.subtrees[0].keys, vec![b"klv1alice".to_vec(), b"klv1bob".to_vec()]);

        s.store_state_checkpoint(100, &cp).unwrap();
        let header = s.load_state_checkpoint_header(100).unwrap().unwrap();
        assert_eq!(header.state_root, root);
        assert_eq!(frame_state_root(&header.subtrees), root);
        for subtree in Subtree::ALL {
            let loaded = s.load_state_checkpoint_subtree(100, subtree).unwrap().unwrap();
            assert_eq!(loaded, cp.subtrees[subtree.index()]);
        }
    }

    #[test]
    fn only_the_newest_heights_are_kept() {
        let (s, _d) = open();
        let cp = s.compute_state_checkpoint().unwrap();
        for h in 1..=(MAX_STATE_CHECKPOINTS as u64 + 3) {
            s.store_state_checkpoint(h * 10, &cp).unwrap();
        }
        let heights = s.state_checkpoint_heights().unwrap();
        let newest = MAX_STATE_CHECKPOINTS as u64 + 3;
        let expected: Vec<u64> =
            ((newest + 1 - MAX_STATE_CHECKPOINTS as u64)..=newest).map(|h| h * 10).collect();
        assert_eq!(heights, expected);
        assert!(s.load_state_checkpoint_subtree(10, Subtree::Users).unwrap().is_none());
    }

    #[test]
    fn the_newest_canonical_checkpoint_survives_pruning() {
        let (s, _d) = open();
        let cp = s.compute_state_checkpoint().unwrap();
        let root = hex::encode(cp.state_root);
        s.store_state_checkpoint(10, &cp).unwrap();
        s.mark_state_checkpoint_canonical(10, &root).unwrap();
        // A mark for a different root or a missing height is ignored.
        s.mark_state_checkpoint_canonical(10, &"00".repeat(32)).unwrap();
        s.mark_state_checkpoint_canonical(999, &root).unwrap();
        assert_eq!(s.canonical_state_checkpoint_heights().unwrap(), vec![10]);
        for h in 2..=(MAX_STATE_CHECKPOINTS as u64 + 3) {
            s.store_state_checkpoint(h * 10, &cp).unwrap();
        }
        let heights = s.state_checkpoint_heights().unwrap();
        assert_eq!(heights.len(), MAX_STATE_CHECKPOINTS + 1);
        assert_eq!(heights[0], 10);
        assert!(s.load_state_checkpoint_subtree(10, Subtree::Users).unwrap().is_some());
        // Re-storing a height clears its mark.
        s.store_state_checkpoint(10, &cp).unwrap();
        assert!(s.canonical_state_checkpoint_heights().unwrap().is_empty());
    }

    #[test]
    fn corrupt_subtree_blobs_are_rejected() {
        assert!(decode_subtree(&[]).is_err());
        assert!(decode_subtree(&[FORMAT_V1, 0, 0, 0, 1]).is_err());
        assert!(decode_subtree(&[FORMAT_V1, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0]).is_err());
        let ok = encode_subtree(&SubtreeCheckpoint {
            keys: vec![b"k".to_vec()],
            leaves: vec![[1u8; 32]],
        })
        .unwrap();
        let mut trailing = ok.clone();
        trailing.push(0);
        assert!(decode_subtree(&trailing).is_err());
        assert!(decode_subtree(&ok[..ok.len() - 1]).is_err());
        assert_eq!(decode_subtree(&ok).unwrap().keys, vec![b"k".to_vec()]);
    }
}
