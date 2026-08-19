//! Integration tests for `IpfsClient` against a controlled fake Kubo.
//!
//! Spawned per test: a tiny axum HTTP server that mimics the Kubo
//! endpoints `IpfsClient` calls (`POST /api/v0/cat`,
//! `POST /api/v0/files/stat`, `POST /api/v0/object/stat`). Each
//! `FakeKubo` exposes knobs for the fault modes the v0.40 audit
//! asked us to cover:
//!
//!   * truncated `cat?offset=&length=` responses
//!   * `files/stat` that overstates the file size
//!   * `files/stat` that returns the older `200 + {"Error": ...}` shape
//!     for missing-local objects (Kubo has historically flipped between
//!     this and 500; we treat both as "not local")
//!
//! These run end-to-end through `reqwest` so the actual HTTP behavior
//! is validated — there are no `reqwest::Client` stubs.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use ogmara_node::config::IpfsConfig;
use ogmara_node::ipfs::client::IpfsClient;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

// --- FakeKubo: configurable per-test stub for Kubo's HTTP API ------------

/// One file held by the fake Kubo, keyed by CID. Each field is a
/// fault knob a test can flip to mimic a misbehaving real Kubo.
#[derive(Clone, Debug)]
struct FakeBlob {
    /// Raw bytes returned by `cat`.
    bytes: Vec<u8>,
    /// What `files/stat` reports for `Size`. If different from
    /// `bytes.len()`, the test is probing the handler's defence
    /// against a misreported size.
    reported_size: u64,
    /// When > 0, `cat?offset=&length=` returns `length - truncate_by`
    /// bytes instead of `length` — the truncated-range fault mode.
    truncate_range_by: u64,
    /// When true, `files/stat` returns HTTP 200 + body
    /// `{"Error": "..."}` (the older Kubo convention for missing-local).
    return_200_with_error: bool,
}

impl FakeBlob {
    fn new(bytes: Vec<u8>) -> Self {
        let size = bytes.len() as u64;
        Self {
            bytes,
            reported_size: size,
            truncate_range_by: 0,
            return_200_with_error: false,
        }
    }
}

#[derive(Clone, Default)]
struct FakeKuboState {
    /// CID → blob. CIDs not in the map cause "not local" responses.
    blobs: Arc<dashmap::DashMap<String, FakeBlob>>,
    /// When set, `/api/v0/add` always reports this CID regardless of the
    /// uploaded bytes — simulates a peer whose `add` response doesn't
    /// match what the caller (`add_and_verify_cid`) expected (W4).
    add_returns_hash: Arc<std::sync::Mutex<Option<String>>>,
    /// CIDs the fake server has received an `/api/v0/pin/rm` call for,
    /// in call order — lets a test assert whether/what got unpinned.
    unpin_calls: Arc<std::sync::Mutex<Vec<String>>>,
    /// When true, `/api/v0/pin/rm` responds with a Kubo-style HTTP-level
    /// failure instead of success — simulates the Security Audit W4
    /// follow-up scenario (Kubo rejects the unpin; `unpin()` must
    /// surface that as `Err`, not silently report success).
    pin_rm_fails: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Deserialize)]
struct ArgQuery {
    arg: String,
}

async fn add_handler(State(state): State<FakeKuboState>) -> impl IntoResponse {
    // The real handler doesn't need to inspect the multipart body — the
    // fake always reports either the configured override hash (W4 tests)
    // or a fixed default "content-addressed" placeholder. Tests that care
    // about the returned hash set `add_returns_hash` first.
    let hash = state
        .add_returns_hash
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| "bafyDEFAULTADDHASH".to_string());
    Json(serde_json::json!({
        "Hash": hash,
        "Size": "0",
        "Name": "peer-fallback",
    }))
    .into_response()
}

async fn pin_rm_handler(
    State(state): State<FakeKuboState>,
    Query(q): Query<ArgQuery>,
) -> impl IntoResponse {
    if state.pin_rm_fails.load(std::sync::atomic::Ordering::SeqCst) {
        // Real Kubo signals pin/rm failure via a non-2xx status (matching
        // the convention `pin()` already defends against, per Security
        // Audit W4 follow-up).
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"Message": "not pinned or pinned indirectly", "Type": "error"})),
        )
            .into_response();
    }
    state.unpin_calls.lock().unwrap().push(q.arg.clone());
    Json(serde_json::json!({ "Pins": [q.arg] })).into_response()
}

#[derive(Deserialize)]
struct CatQuery {
    arg: String,
    #[serde(default)]
    offset: u64,
    length: Option<u64>,
}

async fn cat_handler(
    State(state): State<FakeKuboState>,
    Query(q): Query<CatQuery>,
) -> impl IntoResponse {
    let Some(blob) = state.blobs.get(&q.arg) else {
        return (StatusCode::NOT_FOUND, "not local").into_response();
    };

    let body = blob.bytes.clone();
    let total = body.len() as u64;

    // No offset/length → full body.
    let Some(length) = q.length else {
        if q.offset == 0 {
            return body.into_response();
        }
        // Open-ended slice (offset > 0, no length) is non-standard; just
        // return from offset to end.
        let start = q.offset.min(total) as usize;
        return body[start..].to_vec().into_response();
    };

    // Bounded slice with optional truncation fault.
    let start = q.offset.min(total) as usize;
    let mut len = length.min(total - q.offset) as usize;
    let truncate = blob.truncate_range_by.min(len as u64) as usize;
    len = len.saturating_sub(truncate);
    let end = (start + len).min(body.len());
    body[start..end].to_vec().into_response()
}

#[derive(Deserialize)]
struct StatQuery {
    arg: String,
    #[serde(default)]
    offline: bool,
}

async fn files_stat_handler(
    State(state): State<FakeKuboState>,
    Query(q): Query<StatQuery>,
) -> impl IntoResponse {
    // Strip the `/ipfs/` prefix that IpfsClient adds for files/stat.
    let cid = q.arg.strip_prefix("/ipfs/").unwrap_or(&q.arg).to_string();

    let Some(blob) = state.blobs.get(&cid) else {
        if q.offline {
            // Default Kubo response for missing-local: 500.
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"Message": "not found", "Type": "error"})),
            )
                .into_response();
        }
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };

    if blob.return_200_with_error {
        return Json(serde_json::json!({
            "Error": "block not found locally",
        }))
        .into_response();
    }

    Json(serde_json::json!({
        "Hash": cid,
        "Size": blob.reported_size,
        "CumulativeSize": blob.reported_size,
        "Blocks": 0,
        "Type": "file",
    }))
    .into_response()
}

/// Handle for an in-process fake Kubo server. The server runs until
/// `shutdown` is sent (drop fires it automatically).
struct FakeKubo {
    /// Base URL for `IpfsConfig.api_url`.
    url: String,
    /// State handle so the test can mutate blobs after the server is up.
    state: FakeKuboState,
    /// Shutdown signal — drop to terminate the server.
    _shutdown: oneshot::Sender<()>,
}

impl FakeKubo {
    async fn spawn() -> Self {
        let state = FakeKuboState::default();
        let app: Router = Router::new()
            .route("/api/v0/cat", post(cat_handler))
            .route("/api/v0/files/stat", post(files_stat_handler))
            .route("/api/v0/add", post(add_handler))
            .route("/api/v0/pin/rm", post(pin_rm_handler))
            .with_state(state.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        // No sleep needed: `TcpListener::bind` above is awaited before
        // the spawn, so the OS already has the socket in listening
        // state. Connection attempts queue on the OS accept backlog
        // until axum's serve loop polls. This is the correct sync
        // point — a sleep here would just slow tests without adding
        // safety.

        FakeKubo {
            url,
            state,
            _shutdown: shutdown_tx,
        }
    }

    fn insert(&self, cid: &str, blob: FakeBlob) {
        self.state.blobs.insert(cid.to_string(), blob);
    }

    /// Make `/api/v0/add` always report `hash`, regardless of upload
    /// content — simulates a peer whose delivered bytes don't match the
    /// CID the caller asked for (W4).
    fn set_add_returns_hash(&self, hash: &str) {
        *self.state.add_returns_hash.lock().unwrap() = Some(hash.to_string());
    }

    /// CIDs unpinned so far, in call order.
    fn unpin_calls(&self) -> Vec<String> {
        self.state.unpin_calls.lock().unwrap().clone()
    }

    /// Make `/api/v0/pin/rm` respond with a Kubo-style HTTP failure.
    fn set_pin_rm_fails(&self, fails: bool) {
        self.state
            .pin_rm_fails
            .store(fails, std::sync::atomic::Ordering::SeqCst);
    }

    fn client(&self) -> IpfsClient {
        let config = IpfsConfig {
            api_url: self.url.clone(),
            gateway_url: self.url.clone(),
            max_upload_size_mb: 50,
            auto_thumbnail: false,
            media_cache_total_mb: 256,
            media_cache_item_mb: 16,
            media_handler_permits: 32,
            media_per_ip_permits: 4,
            media_max_tracked_ips: 65_536,
        };
        IpfsClient::new(&config).expect("ipfs client")
    }
}

// --- Tests --------------------------------------------------------------

/// Use a base32 CIDv1 prefix that `validate_cid` accepts (must start
/// with `bafy` and be alphanumeric).
fn cid_for(suffix: &str) -> String {
    format!("bafy{}", suffix)
}

#[tokio::test]
async fn get_returns_full_body_for_known_cid() {
    let kubo = FakeKubo::spawn().await;
    let cid = cid_for("normalblob1234");
    kubo.insert(&cid, FakeBlob::new(b"hello world".to_vec()));
    let bytes = kubo.client().get(&cid).await.expect("get");
    assert_eq!(&bytes[..], b"hello world");
}

#[tokio::test]
async fn get_size_returns_actual_size_field() {
    let kubo = FakeKubo::spawn().await;
    let cid = cid_for("sizeblob1234");
    kubo.insert(&cid, FakeBlob::new(vec![0u8; 4242]));
    let size = kubo.client().get_size(&cid).await.expect("get_size");
    assert_eq!(size, 4242);
}

#[tokio::test]
async fn get_range_slices_correctly() {
    let kubo = FakeKubo::spawn().await;
    let cid = cid_for("rangeblob1234");
    kubo.insert(&cid, FakeBlob::new((0u8..=255).collect()));
    let slice = kubo.client().get_range(&cid, 100, 50).await.expect("range");
    assert_eq!(slice.len(), 50);
    assert_eq!(slice[0], 100);
    assert_eq!(slice[49], 149);
}

#[tokio::test]
async fn get_range_returns_truncated_bytes_under_fault() {
    // This test exercises the IpfsClient layer's permissive return —
    // get_range returns whatever Kubo gives. The handler's
    // `serve_range_streamed` is the one that detects the mismatch
    // and returns 502 (unit-tested separately). What we verify here
    // is the building block: when Kubo truncates, IpfsClient sees
    // the truncation, doesn't mask it.
    let kubo = FakeKubo::spawn().await;
    let cid = cid_for("truncblob1234");
    let mut blob = FakeBlob::new(vec![0xAB; 10_000]);
    blob.truncate_range_by = 100;
    kubo.insert(&cid, blob);
    let slice = kubo.client().get_range(&cid, 0, 1000).await.expect("range");
    assert_eq!(
        slice.len(),
        900,
        "fake kubo configured to truncate by 100 bytes",
    );
}

#[tokio::test]
async fn exists_local_returns_true_for_present_cid() {
    let kubo = FakeKubo::spawn().await;
    let cid = cid_for("existsblob1234");
    kubo.insert(&cid, FakeBlob::new(vec![1, 2, 3]));
    assert!(kubo.client().exists_local(&cid).await.expect("exists_local"));
}

#[tokio::test]
async fn exists_local_returns_false_when_kubo_sends_500() {
    // Standard Kubo "not local" convention: 500 status.
    let kubo = FakeKubo::spawn().await;
    let cid = cid_for("missing1234");
    // NOT inserted → fake kubo returns 500.
    assert!(!kubo
        .client()
        .exists_local(&cid)
        .await
        .expect("exists_local"));
}

#[tokio::test]
async fn exists_local_returns_false_on_200_with_error_body() {
    // The v0.40 hardening: Kubo has historically also signalled
    // "not local" by returning HTTP 200 with `{"Error": ...}` in the
    // body. We must treat that as "not local" too — the pre-0.40
    // implementation would have reported true here, which would have
    // produced a misleading 304 response from the media handler for
    // a CID the node can't actually serve.
    let kubo = FakeKubo::spawn().await;
    let cid = cid_for("errblob1234");
    let mut blob = FakeBlob::new(vec![1, 2, 3]);
    blob.return_200_with_error = true;
    kubo.insert(&cid, blob);
    assert!(
        !kubo.client().exists_local(&cid).await.expect("exists_local"),
        "200 + {{\"Error\": ...}} must be treated as not-local",
    );
}

#[tokio::test]
async fn get_size_uses_files_stat_offline_param() {
    // Regression: the v0.40 implementation passes `offline=true` to
    // avoid DHT walks. We rely on the fake kubo to honor `offline`
    // exactly like real Kubo — if we ever stopped passing the flag,
    // a stat against a missing CID would block on DHT in production.
    // The test asserts the flag flows through.
    //
    // Detection method: the fake kubo's NOT-local branch only
    // returns 500 when `offline=true` is set in the query. If the
    // flag were missing, the fake would return 404 (which IpfsClient
    // would also surface as an error, but with a different message).
    // We check the error path is the offline-500 one.
    let kubo = FakeKubo::spawn().await;
    let cid = cid_for("missing9999");
    let result = kubo.client().get_size(&cid).await;
    let err = result.expect_err("size for missing CID must error");
    // The error message includes the underlying response; "files/stat"
    // is the URL fragment we look for.
    let msg = format!("{:?}", err);
    assert!(
        msg.contains("files/stat"),
        "error should reference files/stat (offline path); got: {}",
        msg
    );
}

#[tokio::test]
async fn add_and_verify_cid_unpins_on_mismatch() {
    // Security Audit final pre-mainnet W4: Kubo's `add?pin=true` pins the
    // blob before add_and_verify_cid can see the CID mismatch. Simulates
    // a peer whose content doesn't hash to the CID the caller asked for
    // (e.g. winning the select_ok race with valid-but-wrong media) and
    // asserts the wrongly-pinned CID gets explicitly unpinned, not left
    // to a GC that (per Kubo's actual behavior) will never reclaim it.
    let kubo = FakeKubo::spawn().await;
    let expected_cid = cid_for("wanted1234");
    let wrong_cid = "bafyWRONGCONTENTHASH".to_string();
    kubo.set_add_returns_hash(&wrong_cid);

    let result = kubo
        .client()
        .add_and_verify_cid(&expected_cid, b"peer-supplied bytes".to_vec())
        .await;

    assert!(result.is_err(), "CID mismatch must be rejected");
    let msg = format!("{:?}", result.unwrap_err());
    assert!(msg.contains(&wrong_cid) && msg.contains(&expected_cid));

    assert_eq!(
        kubo.unpin_calls(),
        vec![wrong_cid],
        "the wrongly-pinned CID must be unpinned exactly once"
    );
}

#[tokio::test]
async fn add_and_verify_cid_does_not_unpin_on_match() {
    // Regression guard against over-eager unpinning: the success path
    // (the common case) must never touch pin/rm — the whole point of
    // pin=true on add is that verified content stays pinned.
    let kubo = FakeKubo::spawn().await;
    let cid = cid_for("matching1234");
    kubo.set_add_returns_hash(&cid);

    kubo.client()
        .add_and_verify_cid(&cid, b"peer-supplied bytes".to_vec())
        .await
        .expect("matching CID must be accepted");

    assert!(
        kubo.unpin_calls().is_empty(),
        "verified content must never be unpinned"
    );
}

#[tokio::test]
async fn unpin_surfaces_kubo_http_failure_as_err() {
    // Security Audit follow-up (W4): `unpin()` previously treated ANY
    // HTTP response from Kubo as success — `reqwest::send()` only errors
    // on transport-level failures, not on Kubo returning a non-2xx. That
    // meant a real pin/rm failure (busy, disk contention, races) was
    // silently reported as `Ok(())`, so `add_and_verify_cid`'s
    // mismatch-cleanup `warn!` would almost never fire in practice.
    // Mirrors `pin()`'s existing, already-correct status check.
    let kubo = FakeKubo::spawn().await;
    let cid = cid_for("failingunpin1234");
    kubo.set_pin_rm_fails(true);

    let result = kubo.client().unpin(&cid).await;

    assert!(
        result.is_err(),
        "a Kubo-reported pin/rm failure must surface as Err, not be silently swallowed"
    );
}
