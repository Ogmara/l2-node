//! `GET /api/v1/state/proof` — record inclusion proofs against an anchored
//! state root (spec 03 §3.6 / §4.1, spec 02 §7, l2-node 0.147.0+).
//!
//! Proves that a user, channel, delegation or channel-membership record is
//! part of the state root this node anchored at a block height. The node is
//! not trusted: the client rebuilds the subtree root from the record's value,
//! index and sibling path, frames it with the other three subtree
//! `(count, root)` pairs into the state root, and compares that with the
//! Klever SC's `getCanonicalAnchor(block_height)` (sdk `verifyStateProof`).
//!
//! Scope and refusals:
//! - Only nodes with `[anchoring] enabled` store checkpoints; others answer
//!   `404 no_checkpoint`. The newest [`MAX_STATE_CHECKPOINTS`] heights are
//!   kept, plus the newest one confirmed canonical. Without `height` the
//!   newest canonical-confirmed checkpoint is used (else the newest); the
//!   response's `canonical_confirmed` is a hint only — clients verify
//!   against the chain.
//! - The proof carries the record's CURRENT value. If it changed after the
//!   checkpoint the node answers `409 record_changed` instead of proving a
//!   value it no longer has; retry after the next anchor.
//! - Private channels (and their memberships) are refused: a public
//!   membership proof would reveal who is in a private channel.
//!
//! Cost per request: one header read, a binary search and an O(log n) path
//! read from a cached tree. Building a subtree's tree is O(n) hashing; it
//! runs on the blocking pool, one build at a time node-wide — a request that
//! needs a build while another runs gets `503 busy` instead of parking a
//! blocking thread — and the result is cached per (state root, subtree).
//!
//! [`MAX_STATE_CHECKPOINTS`]: crate::storage::state_checkpoints::MAX_STATE_CHECKPOINTS

use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::{Extension, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::Deserialize;

use crate::crypto::merkle::{inclusion_path, tree_levels};
use crate::messages::types::PRIVATE_CHANNEL_ID_FLOOR;
use crate::storage::rocks::Storage;
use crate::storage::schema;
use crate::storage::state_checkpoints::Subtree;

use super::state::AppState;

/// Longest address / device key accepted (klv1 addresses are 62 chars,
/// device keys 64 hex chars).
const MAX_ID_LEN: usize = 128;
/// Cached subtree trees: two checkpoints' worth. Entries for the default
/// (canonical-confirmed) height are evicted last, so clients cycling
/// explicit heights cannot push the commonly requested trees out.
const CACHE_ENTRIES: usize = 8;

/// Query parameters. Which ones are required depends on `subtree`:
/// `users` → `address`; `channels` → `channel_id`; `delegations` →
/// `address` + `device_key`; `channel_members` → `channel_id` + `address`.
#[derive(Debug, Deserialize)]
pub struct StateProofQuery {
    pub subtree: String,
    pub address: Option<String>,
    pub channel_id: Option<u64>,
    pub device_key: Option<String>,
    /// Checkpoint height; defaults to the newest stored one.
    pub height: Option<u64>,
}

/// A subtree's keys plus every tree level, built once per checkpoint.
struct CachedTree {
    keys: Vec<Vec<u8>>,
    levels: Vec<Vec<[u8; 32]>>,
}

type CacheKey = ([u8; 32], u8);

fn cache() -> &'static Mutex<Vec<(CacheKey, Arc<CachedTree>)>> {
    static CACHE: OnceLock<Mutex<Vec<(CacheKey, Arc<CachedTree>)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Vec::new()))
}

/// Serialises tree builds node-wide (each is O(n) hashing).
fn build_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn cached(key: &CacheKey) -> Option<Arc<CachedTree>> {
    let guard = cache().lock().unwrap_or_else(|p| p.into_inner());
    guard.iter().find(|(k, _)| k == key).map(|(_, t)| t.clone())
}

/// The tree for `subtree` at `height` (whose header says `state_root`),
/// from the cache or built from the stored checkpoint. Blocking.
fn tree_for(
    storage: &Storage,
    height: u64,
    state_root: [u8; 32],
    subtree: Subtree,
    default_root: Option<[u8; 32]>,
) -> anyhow::Result<Option<Arc<CachedTree>>> {
    tree_for_with(build_lock(), storage, height, state_root, subtree, default_root)
}

/// [`tree_for`] with an explicit build lock (tests use their own).
/// `default_root` is the root of the default height; its entries are
/// evicted last.
fn tree_for_with(
    lock: &Mutex<()>,
    storage: &Storage,
    height: u64,
    state_root: [u8; 32],
    subtree: Subtree,
    default_root: Option<[u8; 32]>,
) -> anyhow::Result<Option<Arc<CachedTree>>> {
    let key = (state_root, subtree as u8);
    if let Some(tree) = cached(&key) {
        return Ok(Some(tree));
    }
    let _build = match lock.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return Err(Busy.into()),
    };
    // Another request may have built it just before we got the lock.
    if let Some(tree) = cached(&key) {
        return Ok(Some(tree));
    }
    let Some(st) = storage.load_state_checkpoint_subtree(height, subtree)? else {
        return Ok(None);
    };
    let tree = Arc::new(CachedTree {
        levels: tree_levels(&st.leaves),
        keys: st.keys,
    });
    let mut guard = cache().lock().unwrap_or_else(|p| p.into_inner());
    if guard.len() >= CACHE_ENTRIES {
        let keys: Vec<CacheKey> = guard.iter().map(|(k, _)| *k).collect();
        guard.remove(eviction_victim(&keys, default_root));
    }
    guard.push((key, tree.clone()));
    Ok(Some(tree))
}

/// Another tree build is running; the caller should retry shortly.
#[derive(Debug)]
struct Busy;

impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a state proof build is already running")
    }
}

impl std::error::Error for Busy {}

/// Index of the cache entry to evict: the oldest one NOT belonging to the
/// default height's root, else the oldest overall.
fn eviction_victim(keys: &[CacheKey], default_root: Option<[u8; 32]>) -> usize {
    keys.iter()
        .position(|(root, _)| Some(*root) != default_root)
        .unwrap_or(0)
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": code, "message": message }))).into_response()
}

fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_ID_LEN && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Refuse private channels, failing closed on missing metadata.
fn channel_is_public(storage: &Storage, channel_id: u64) -> bool {
    if channel_id >= PRIVATE_CHANNEL_ID_FLOOR {
        return false;
    }
    matches!(storage.get_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes()), Ok(Some(_)))
        && !crate::network::reconcile::is_private_channel(storage, channel_id)
}

/// The RocksDB key of the requested record, or an error response.
fn record_key(q: &StateProofQuery, subtree: Subtree) -> Result<Vec<u8>, Response> {
    let address = || match q.address.as_deref() {
        Some(a) if valid_id(a) => Ok(a),
        _ => Err(error(StatusCode::BAD_REQUEST, "bad_request", "missing or invalid address")),
    };
    let channel_id = || {
        q.channel_id
            .ok_or_else(|| error(StatusCode::BAD_REQUEST, "bad_request", "missing channel_id"))
    };
    Ok(match subtree {
        Subtree::Users => address()?.as_bytes().to_vec(),
        Subtree::Channels => channel_id()?.to_be_bytes().to_vec(),
        Subtree::Delegations => {
            let device_key = match q.device_key.as_deref() {
                Some(d) if valid_id(d) => d,
                _ => {
                    return Err(error(
                        StatusCode::BAD_REQUEST,
                        "bad_request",
                        "missing or invalid device_key",
                    ))
                }
            };
            schema::encode_delegation_key(address()?, device_key)
        }
        Subtree::ChannelMembers => schema::encode_channel_member_key(channel_id()?, address()?),
    })
}

/// GET /api/v1/state/proof — see the module docs.
pub async fn get_state_proof(
    Extension(state): Extension<Arc<AppState>>,
    Query(q): Query<StateProofQuery>,
) -> Response {
    let Some(subtree) = Subtree::ALL.into_iter().find(|s| s.name() == q.subtree) else {
        return error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "subtree must be users, channels, delegations or channel_members",
        );
    };
    let key = match record_key(&q, subtree) {
        Ok(k) => k,
        Err(resp) => return resp,
    };
    let storage = state.storage.clone();
    let height = q.height;
    let channel_id = q.channel_id;
    match tokio::task::spawn_blocking(move || build_proof(&storage, subtree, &key, height, channel_id))
        .await
    {
        Ok(resp) => resp,
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal", "proof task failed"),
    }
}

/// Blocking body of [`get_state_proof`].
fn build_proof(
    storage: &Storage,
    subtree: Subtree,
    key: &[u8],
    height: Option<u64>,
    channel_id: Option<u64>,
) -> Response {
    let internal = |e: anyhow::Error| {
        tracing::warn!(error = %e, "state proof failed");
        error(StatusCode::INTERNAL_SERVER_ERROR, "internal", "could not read the state checkpoint")
    };
    if matches!(subtree, Subtree::Channels | Subtree::ChannelMembers) {
        if let Some(id) = channel_id {
            if !channel_is_public(storage, id) {
                return error(
                    StatusCode::FORBIDDEN,
                    "private_channel",
                    "proofs are only served for existing public channels (private, unknown and deleted channels are refused)",
                );
            }
        }
    }

    let canonical = match storage.canonical_state_checkpoint_heights() {
        Ok(c) => c,
        Err(e) => return internal(e),
    };
    let default_height = match storage.state_checkpoint_heights() {
        Ok(heights) => canonical.last().or(heights.last()).copied(),
        Err(e) => return internal(e),
    };
    let Some(height) = height.or(default_height) else {
        return error(
            StatusCode::NOT_FOUND,
            "no_checkpoint",
            "this node stores no anchored state checkpoint (anchoring disabled or no anchor yet)",
        );
    };
    let header = match storage.load_state_checkpoint_header(height) {
        Ok(Some(h)) => h,
        Ok(None) => {
            return error(
                StatusCode::NOT_FOUND,
                "no_checkpoint",
                "no state checkpoint stored for this height",
            )
        }
        Err(e) => return internal(e),
    };
    let default_root = if Some(height) == default_height {
        Some(header.state_root)
    } else {
        match default_height.map(|h| storage.load_state_checkpoint_header(h)) {
            Some(Ok(Some(h))) => Some(h.state_root),
            // Only an eviction hint: never fail another height's proof on it.
            Some(Err(e)) => {
                tracing::warn!(error = %e, "unreadable default state checkpoint header");
                None
            }
            _ => None,
        }
    };
    let tree = match tree_for(storage, height, header.state_root, subtree, default_root) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return error(StatusCode::NOT_FOUND, "no_checkpoint", "state checkpoint is incomplete")
        }
        Err(e) if e.is::<Busy>() => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "busy",
                "another state proof is being prepared; retry shortly",
            )
        }
        Err(e) => return internal(e),
    };
    let Ok(index) = tree.keys.binary_search_by(|k| k.as_slice().cmp(key)) else {
        return error(
            StatusCode::NOT_FOUND,
            "not_in_checkpoint",
            "the record is not part of the state at this checkpoint",
        );
    };
    let value = match storage.get_cf(subtree.cf(), key) {
        Ok(v) => v,
        Err(e) => return internal(e),
    };
    let leaf = tree.levels[0][index];
    let Some(value) = value.filter(|v| subtree.leaf(key, v) == leaf) else {
        return error(
            StatusCode::CONFLICT,
            "record_changed",
            "the record changed after this checkpoint; retry after the next anchor",
        );
    };
    let Some(siblings) = inclusion_path(&tree.levels, index) else {
        return internal(anyhow::anyhow!("index {index} outside its own tree"));
    };

    let subtrees: Vec<_> = Subtree::ALL
        .iter()
        .map(|s| {
            let (count, root) = header.subtrees[s.index()];
            serde_json::json!({ "name": s.name(), "count": count, "root": hex::encode(root) })
        })
        .collect();
    Json(serde_json::json!({
        "block_height": header.block_height,
        "state_root": hex::encode(header.state_root),
        "canonical_confirmed": canonical.contains(&header.block_height),
        "subtree": subtree.name(),
        "key": hex::encode(key),
        "value": base64::engine::general_purpose::STANDARD.encode(&value),
        "leaf": hex::encode(leaf),
        "leaf_index": index,
        "leaf_count": tree.keys.len(),
        "siblings": siblings.iter().map(hex::encode).collect::<Vec<_>>(),
        "subtrees": subtrees,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::merkle::{frame_state_root, root_from_path};
    use crate::storage::schema::cf;

    fn open() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    async fn body(resp: Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn hex32(v: &serde_json::Value) -> [u8; 32] {
        hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
    }

    /// Verify a proof response the way a client does: value → leaf, path →
    /// subtree root, framing → state root.
    fn verify(p: &serde_json::Value) -> bool {
        let subtree = Subtree::ALL
            .into_iter()
            .find(|s| s.name() == p["subtree"])
            .unwrap();
        let key = hex::decode(p["key"].as_str().unwrap()).unwrap();
        let value = base64::engine::general_purpose::STANDARD
            .decode(p["value"].as_str().unwrap())
            .unwrap();
        let leaf = subtree.leaf(&key, &value);
        let siblings: Vec<[u8; 32]> = p["siblings"].as_array().unwrap().iter().map(hex32).collect();
        let Some(sub_root) = root_from_path(
            leaf,
            p["leaf_index"].as_u64().unwrap(),
            p["leaf_count"].as_u64().unwrap(),
            &siblings,
        ) else {
            return false;
        };
        let mut framed = [(0u64, [0u8; 32]); 4];
        for (i, st) in p["subtrees"].as_array().unwrap().iter().enumerate() {
            framed[i] = (st["count"].as_u64().unwrap(), hex32(&st["root"]));
        }
        framed[subtree.index()].1 == sub_root
            && framed[subtree.index()].0 == p["leaf_count"].as_u64().unwrap()
            && frame_state_root(&framed) == hex32(&p["state_root"])
    }

    fn seed(s: &Storage) {
        for i in 0..5 {
            let a = format!("klv1user{i}");
            s.put_cf(cf::USERS, a.as_bytes(), format!(r#"{{"address":"{a}"}}"#).as_bytes())
                .unwrap();
        }
        s.put_cf(cf::CHANNELS, &3u64.to_be_bytes(), br#"{"channel_id":3,"channel_type":0}"#)
            .unwrap();
        s.put_cf(cf::CHANNELS, &4u64.to_be_bytes(), br#"{"channel_id":4,"channel_type":2}"#)
            .unwrap();
        for (ch, who) in [(3u64, "klv1user1"), (4, "klv1user2")] {
            s.put_cf(
                cf::CHANNEL_MEMBERS,
                &schema::encode_channel_member_key(ch, who),
                br#"{"role":"member"}"#,
            )
            .unwrap();
        }
    }

    fn query(subtree: &str, address: Option<&str>, channel_id: Option<u64>) -> StateProofQuery {
        StateProofQuery {
            subtree: subtree.into(),
            address: address.map(Into::into),
            channel_id,
            device_key: None,
            height: None,
        }
    }

    fn proof(s: &Storage, q: &StateProofQuery) -> Response {
        let subtree = Subtree::ALL.into_iter().find(|x| x.name() == q.subtree).unwrap();
        let key = record_key(q, subtree).map_err(|_| ()).unwrap();
        build_proof(s, subtree, &key, q.height, q.channel_id)
    }

    #[tokio::test]
    async fn proofs_verify_against_the_anchored_root() {
        let (s, _d) = open();
        seed(&s);
        let cp = s.compute_state_checkpoint().unwrap();
        s.store_state_checkpoint(500, &cp).unwrap();

        for q in [
            query("users", Some("klv1user0"), None),
            query("users", Some("klv1user4"), None),
            query("channels", None, Some(3)),
            query("channel_members", Some("klv1user1"), Some(3)),
        ] {
            let (status, p) = body(proof(&s, &q)).await;
            assert_eq!(status, StatusCode::OK, "{p}");
            assert_eq!(p["block_height"], 500);
            assert_eq!(hex32(&p["state_root"]), cp.state_root);
            assert!(verify(&p), "{p}");
        }
    }

    #[tokio::test]
    async fn changed_missing_and_private_records_are_refused() {
        let (s, _d) = open();
        seed(&s);
        let cp = s.compute_state_checkpoint().unwrap();
        s.store_state_checkpoint(500, &cp).unwrap();

        s.put_cf(cf::USERS, b"klv1user0", br#"{"address":"klv1user0","x":1}"#).unwrap();
        let (status, p) = body(proof(&s, &query("users", Some("klv1user0"), None))).await;
        assert_eq!((status, p["error"].as_str()), (StatusCode::CONFLICT, Some("record_changed")));

        let (status, p) = body(proof(&s, &query("users", Some("klv1nobody"), None))).await;
        assert_eq!(
            (status, p["error"].as_str()),
            (StatusCode::NOT_FOUND, Some("not_in_checkpoint"))
        );

        for q in [
            query("channels", None, Some(4)),
            query("channel_members", Some("klv1user2"), Some(4)),
            query("channel_members", Some("klv1user1"), Some(99)),
            query("channels", None, Some(PRIVATE_CHANNEL_ID_FLOOR)),
        ] {
            let (status, p) = body(proof(&s, &q)).await;
            assert_eq!(
                (status, p["error"].as_str()),
                (StatusCode::FORBIDDEN, Some("private_channel")),
                "{q:?}"
            );
        }
    }

    #[tokio::test]
    async fn default_height_prefers_the_newest_canonical_checkpoint() {
        let (s, _d) = open();
        seed(&s);
        let cp = s.compute_state_checkpoint().unwrap();
        s.store_state_checkpoint(100, &cp).unwrap();
        s.store_state_checkpoint(200, &cp).unwrap();
        let q = query("users", Some("klv1user0"), None);
        let (_, p) = body(proof(&s, &q)).await;
        assert_eq!((p["block_height"].as_u64(), p["canonical_confirmed"].as_bool()), (Some(200), Some(false)));

        s.mark_state_checkpoint_canonical(100, &hex::encode(cp.state_root)).unwrap();
        let (_, p) = body(proof(&s, &q)).await;
        assert_eq!((p["block_height"].as_u64(), p["canonical_confirmed"].as_bool()), (Some(100), Some(true)));
        assert!(verify(&p));
    }

    #[test]
    fn a_build_in_progress_answers_busy_instead_of_waiting() {
        let (s, _d) = open();
        seed(&s);
        // A state no other test produces, so its tree is never cached.
        s.put_cf(cf::USERS, b"klv1busy", br#"{"address":"klv1busy"}"#).unwrap();
        let cp = s.compute_state_checkpoint().unwrap();
        s.store_state_checkpoint(7, &cp).unwrap();
        let lock = Mutex::new(());
        let guard = lock.lock().unwrap();
        let Err(err) = tree_for_with(&lock, &s, 7, cp.state_root, Subtree::Users, None) else {
            panic!("expected Busy while the build lock is held");
        };
        assert!(err.is::<Busy>());
        drop(guard);
        assert!(tree_for_with(&lock, &s, 7, cp.state_root, Subtree::Users, None).unwrap().is_some());
    }

    #[tokio::test]
    async fn a_node_without_checkpoints_says_so() {
        let (s, _d) = open();
        seed(&s);
        let (status, p) = body(proof(&s, &query("users", Some("klv1user0"), None))).await;
        assert_eq!((status, p["error"].as_str()), (StatusCode::NOT_FOUND, Some("no_checkpoint")));
    }

    /// Known-answer vector shared with sdk-js `verifyStateProof` tests: the
    /// same fixed rows must always produce this root and proof (the SDK
    /// test embeds this proof verbatim). If this changes, the anchored root format
    /// changed — every node and the SDK fixture must move together.
    #[tokio::test]
    async fn known_answer_vector() {
        let (s, _d) = open();
        seed(&s);
        let cp = s.compute_state_checkpoint().unwrap();
        s.store_state_checkpoint(500, &cp).unwrap();
        let (_, p) = body(proof(&s, &query("channel_members", Some("klv1user1"), Some(3)))).await;
        assert!(verify(&p));
        // Odd-count subtree, last leaf (paired with itself at level 0).
        let (_, users) = body(proof(&s, &query("users", Some("klv1user4"), None))).await;
        assert!(verify(&users));
        assert_eq!(users["leaf_index"], 4);
        if std::env::var_os("OGMARA_PRINT_VECTORS").is_some() {
            println!("VECTOR {p}");
            println!("VECTOR {users}");
        }
        assert_eq!(p["leaf"], "04cc4282fbb9ef6dc1e69de83409e26eb8c361846fb6d037378ccded537fcad2");
        assert_eq!(
            hex::encode(cp.state_root),
            "099064e5796505367550de365185ed7aed10e3fd80189299012012eb16a4eaef"
        );
    }

    #[test]
    fn eviction_spares_the_default_heights_trees() {
        let (d, x, y) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let keys = [(d, 0), (d, 1), (x, 0), (y, 0)];
        assert_eq!(eviction_victim(&keys, Some(d)), 2);
        assert_eq!(eviction_victim(&keys, None), 0);
        assert_eq!(eviction_victim(&[(d, 0), (d, 1)], Some(d)), 0);
    }

    #[test]
    fn bad_ids_are_rejected() {
        assert!(record_key(&query("users", Some("klv1/../x"), None), Subtree::Users).is_err());
        assert!(record_key(&query("users", None, None), Subtree::Users).is_err());
        assert!(record_key(&query("channels", None, None), Subtree::Channels).is_err());
        let long = "a".repeat(MAX_ID_LEN + 1);
        assert!(record_key(&query("users", Some(&long), None), Subtree::Users).is_err());
    }
}
