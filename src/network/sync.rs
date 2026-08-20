//! Sync protocol — request-response for on-demand content fetching.
//!
//! When a node doesn't have content locally, it asks peers that do
//! via the sync protocol (spec 5.5). This uses libp2p's request-response
//! behaviour with CBOR encoding.

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::storage::rocks::Storage;

/// Sync request sent to a peer (spec 5.5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    /// What type of content to fetch.
    pub request_type: SyncRequestType,
    /// Channel ID (for channel messages).
    pub channel_id: Option<u64>,
    /// Conversation ID (for DMs).
    pub conversation_id: Option<[u8; 32]>,
    /// Pagination: messages before this ID.
    pub before_id: Option<[u8; 32]>,
    /// Pagination: messages after this ID.
    pub after_id: Option<[u8; 32]>,
    /// Messages after this timestamp.
    pub after_timestamp: Option<u64>,
    /// Max messages to return (capped at 500).
    pub limit: u32,
}

/// Type of content being requested.
///
/// Audit final pre-mainnet W8: `PrivateChannelMessages`/`PrivateChannelKeys`
/// (0x07/0x08) — and the `requester`/`proof`/`proof_timestamp` auth fields on
/// `SyncRequest` they alone used, and `verify_private_channel_access` —
/// removed. Confirmed unreachable: no caller anywhere in the org (not even
/// l2-node's own outbound sync client) ever constructed one; the auth
/// preimage was also not host-bound (no responder PeerId/network), so a
/// malicious node could have replayed a captured proof elsewhere within its
/// 5-minute window — moot now that nothing can produce a real proof in the
/// first place. Private-channel key delivery works via the separate,
/// actually-used `PrivateChannelKeyDistribution` gossip message instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SyncRequestType {
    ChannelMessages = 0x01,
    DirectMessages = 0x02,
    NewsPosts = 0x03,
    NewsPostsByTag = 0x04,
    UserPosts = 0x05,
}

/// Sync response from a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    /// The request type this is responding to.
    pub request_type: SyncRequestType,
    /// Serialized Envelope bytes for each message.
    pub messages: Vec<Vec<u8>>,
    /// Whether more data is available (pagination).
    pub has_more: bool,
    /// `true` when the responder hit its per-peer or per-channel rate limit
    /// (audit final pre-mainnet W7). `messages` is empty in this case; the
    /// requester should back off and retry later. `#[serde(default)]` keeps
    /// old-shaped CBOR bytes decodable (decodes to `false`) — no protocol
    /// version bump needed, mirrors every sibling response type
    /// (`ReconcileResponse`/`DmSyncResponse`/`NewsSyncResponse`) which
    /// already has this field.
    #[serde(default)]
    pub server_capped: bool,
}

/// Codec type alias for the sync protocol.
pub type SyncCodec = libp2p::request_response::cbor::Behaviour<SyncRequest, SyncResponse>;

/// Build a sync response from local storage for an incoming request.
pub fn build_sync_response(request: SyncRequest, storage: &Storage) -> SyncResponse {
    let limit = request.limit.min(500) as usize;

    let messages = match request.request_type {
        SyncRequestType::ChannelMessages => {
            if let Some(channel_id) = request.channel_id {
                fetch_channel_messages(storage, channel_id, &request, limit)
            } else {
                Vec::new()
            }
        }
        // Other request types will be implemented as storage queries are built out
        _ => Vec::new(),
    };

    let has_more = messages.len() == limit;

    SyncResponse {
        request_type: request.request_type,
        messages,
        has_more,
        server_capped: false,
    }
}

// --- Responder rate limiting (audit final pre-mainnet W7) ---
//
// `ChannelMessages` (the only request type with a live requester —
// `DirectMessages`/`NewsPosts`/`NewsPostsByTag`/`UserPosts` are unimplemented
// stubs; `PrivateChannelMessages`/`PrivateChannelKeys` were removed, audit
// final pre-mainnet W8, confirmed unreachable) is `(peer, channel_id)`-shaped
// — identical to `reconcile::ReconcileRequest`'s key space, since both are
// "per-channel content fetch" protocols. `network/mod.rs` reuses
// `reconcile::ResponderLimits`/`ResponderGuard` directly rather than
// duplicating them here.

/// Per-peer concurrency cap for inbound sync requests, mirroring
/// `[backfill] server_max_concurrent_per_peer`'s default.
pub const SERVER_MAX_CONCURRENT_PER_PEER: usize = 4;
/// Per-(peer, channel) concurrency cap, mirroring
/// `[backfill] server_max_concurrent_per_channel`'s default.
pub const SERVER_MAX_CONCURRENT_PER_CHANNEL: usize = 1;
/// Cumulative envelopes one (peer, channel) pair may pull per process
/// lifetime. Smaller than reconcile's 200_000 default: sync.rs is an
/// incremental reconnect-catchup protocol (bounded by `after_timestamp`),
/// not a bulk full-history transfer.
pub const TOTAL_ENVELOPES_CAP: u64 = 5_000;

/// Construct a `server_capped` response (no envelopes) — used when the
/// per-peer or per-channel rate limit denies the request (audit final
/// pre-mainnet W7).
pub fn capped_response(request_type: SyncRequestType) -> SyncResponse {
    SyncResponse {
        request_type,
        messages: Vec::new(),
        has_more: false,
        server_capped: true,
    }
}

/// Fetch channel messages from storage using the channel_msgs index.
///
/// If `after_timestamp` is set, only returns messages with Lamport timestamp
/// strictly greater than the given value (used for incremental sync).
fn fetch_channel_messages(
    storage: &Storage,
    channel_id: u64,
    request: &SyncRequest,
    limit: usize,
) -> Vec<Vec<u8>> {
    use crate::storage::schema::cf;

    let prefix = channel_id.to_be_bytes();

    // Build seek key: if after_timestamp is set, start scanning after that timestamp
    let seek_key = if let Some(after_ts) = request.after_timestamp {
        let mut key = Vec::with_capacity(16);
        key.extend_from_slice(&prefix);
        key.extend_from_slice(&(after_ts + 1).to_be_bytes());
        key
    } else {
        prefix.to_vec()
    };

    // Iterate from the seek position, but use the channel_id prefix to bound the scan
    match storage.iter_cf_from(cf::CHANNEL_MSGS, &seek_key, &prefix, limit) {
        Ok(entries) => {
            let mut messages = Vec::with_capacity(entries.len());
            for (key, _) in entries {
                // Key format: (channel_id:8, lamport_ts:8, msg_id:32)
                if key.len() >= 48 {
                    let msg_id: [u8; 32] = key[16..48].try_into().unwrap_or([0u8; 32]);
                    if let Ok(Some(envelope_bytes)) = storage.get_message(&msg_id) {
                        messages.push(envelope_bytes);
                    }
                }
            }
            messages
        }
        Err(e) => {
            warn!(error = %e, channel_id, "Failed to fetch channel messages");
            Vec::new()
        }
    }
}
