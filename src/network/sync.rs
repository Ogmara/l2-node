//! Sync protocol — request-response for on-demand content fetching.
//!
//! When a node doesn't have content locally, it asks peers that do
//! via the sync protocol (spec 5.5). This uses libp2p's request-response
//! behaviour with CBOR encoding.

use libp2p::request_response;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::messages::router::{MessageRouter, RouteResult};
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
}

/// Codec type alias for the sync protocol.
pub type SyncCodec = libp2p::request_response::cbor::Behaviour<SyncRequest, SyncResponse>;

/// Handle a request-response event from the swarm.
pub fn handle_request_response_event(
    event: request_response::Event<SyncRequest, SyncResponse>,
    storage: &Storage,
    router: &MessageRouter,
) {
    match event {
        request_response::Event::Message {
            peer,
            message:
                request_response::Message::Request {
                    request,
                    channel,
                    ..
                },
            ..
        } => {
            debug!(
                peer = %peer,
                request_type = ?request.request_type,
                channel_id = ?request.channel_id,
                "Received sync request"
            );

            // Build response from local storage
            let response = handle_sync_request(request, storage);

            debug!(
                messages = response.messages.len(),
                has_more = response.has_more,
                "Sync response prepared"
            );
        }

        request_response::Event::Message {
            peer,
            message:
                request_response::Message::Response {
                    response,
                    ..
                },
            ..
        } => {
            debug!(
                peer = %peer,
                messages = response.messages.len(),
                has_more = response.has_more,
                "Received sync response"
            );

            // Validate and store each message through the full pipeline
            let mut accepted = 0u32;
            let mut rejected = 0u32;
            for msg_bytes in &response.messages {
                match router.process_message(msg_bytes) {
                    RouteResult::Accepted { .. } => accepted += 1,
                    RouteResult::Duplicate => {} // expected during sync
                    RouteResult::Rejected(reason) => {
                        warn!(reason = %reason, "Rejected synced message");
                        rejected += 1;
                    }
                }
            }
            debug!(accepted, rejected, "Sync response processed");
        }

        request_response::Event::OutboundFailure {
            peer, error, ..
        } => {
            warn!(peer = %peer, error = %error, "Sync request failed");
        }

        request_response::Event::InboundFailure {
            peer, error, ..
        } => {
            warn!(peer = %peer, error = %error, "Sync inbound failure");
        }

        _ => {}
    }
}

/// Handle a sync request by querying local storage.
fn handle_sync_request(request: SyncRequest, storage: &Storage) -> SyncResponse {
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
    }
}

/// Fetch channel messages from storage using the channel_msgs index.
fn fetch_channel_messages(
    storage: &Storage,
    channel_id: u64,
    _request: &SyncRequest,
    limit: usize,
) -> Vec<Vec<u8>> {
    use crate::storage::schema::cf;

    // Build prefix for the channel_msgs column family
    let prefix = channel_id.to_be_bytes();

    // Query the index to get msg_ids, then fetch full envelopes
    match storage.prefix_iter_cf(cf::CHANNEL_MSGS, &prefix, limit) {
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
