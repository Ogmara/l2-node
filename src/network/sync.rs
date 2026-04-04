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
    /// Requester address for authenticated requests (PrivateChannelMessages/Keys).
    #[serde(default)]
    pub requester: Option<String>,
    /// Ed25519 signature proof for authenticated requests.
    #[serde(default)]
    pub proof: Option<Vec<u8>>,
    /// Timestamp used in the proof signature (replay protection).
    #[serde(default)]
    pub proof_timestamp: Option<u64>,
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
    /// Authenticated request for private channel messages (anchor node verifies membership).
    PrivateChannelMessages = 0x07,
    /// Authenticated request for private channel key material.
    PrivateChannelKeys = 0x08,
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
        SyncRequestType::PrivateChannelMessages => {
            if let Some(channel_id) = request.channel_id {
                match verify_private_channel_access(storage, &request, channel_id) {
                    Ok(()) => fetch_channel_messages(storage, channel_id, &request, limit),
                    Err(reason) => {
                        warn!(channel_id, reason = %reason, "Private channel access denied");
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            }
        }
        SyncRequestType::PrivateChannelKeys => {
            if let Some(channel_id) = request.channel_id {
                match verify_private_channel_access(storage, &request, channel_id) {
                    Ok(()) => fetch_private_channel_keys(storage, channel_id),
                    Err(reason) => {
                        warn!(channel_id, reason = %reason, "Private channel key access denied");
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            }
        }
        // Other request types will be implemented as storage queries are built out
        _ => Vec::new(),
    };

    // PrivateChannelKeys always returns at most 1 entry (latest epoch) — never paginated
    let has_more = match request.request_type {
        SyncRequestType::PrivateChannelKeys => false,
        _ => messages.len() == limit,
    };

    SyncResponse {
        request_type: request.request_type,
        messages,
        has_more,
    }
}

/// Verify that a private channel sync request is authorized.
///
/// Checks: (1) requester address is provided, (2) requester is a member of the channel,
/// (3) signature proof is valid. Returns Ok(()) if access is granted.
fn verify_private_channel_access(
    storage: &Storage,
    request: &SyncRequest,
    channel_id: u64,
) -> Result<(), String> {
    use crate::storage::schema::{cf, encode_channel_member_key};

    let requester = request.requester.as_ref()
        .ok_or_else(|| "requester address required for private channel access".to_string())?;

    // Verify the requester is a member of the channel
    let member_key = encode_channel_member_key(channel_id, requester);
    let is_member = storage.exists_cf(cf::CHANNEL_MEMBERS, &member_key)
        .map_err(|e| format!("storage error: {}", e))?;

    if !is_member {
        // Generic error — don't reveal whether the channel exists
        return Err("access denied".into());
    }

    // Verify the proof signature (requester signs: channel_id ++ timestamp ++ requester_bytes)
    let proof = request.proof.as_ref()
        .ok_or_else(|| "proof signature required".to_string())?;
    let proof_ts = request.proof_timestamp
        .ok_or_else(|| "proof_timestamp required".to_string())?;

    // Check timestamp is within ±5 minutes (replay protection)
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let drift = if now_ms > proof_ts { now_ms - proof_ts } else { proof_ts - now_ms };
    if drift > 300_000 {
        return Err("proof timestamp too old or in the future".into());
    }

    // Build domain-separated signed data and hash with Keccak-256 (consistent with
    // the rest of the Ogmara protocol). The domain prefix prevents cross-protocol
    // signature confusion.
    let mut preimage = Vec::with_capacity(32 + 8 + 8 + requester.len());
    preimage.extend_from_slice(b"ogmara-private-channel-access:");
    preimage.extend_from_slice(&channel_id.to_be_bytes());
    preimage.extend_from_slice(&proof_ts.to_be_bytes());
    preimage.extend_from_slice(requester.as_bytes());
    let signed_hash = crate::crypto::keccak256(&preimage);

    // Verify Ed25519 signature over the Keccak-256 hash
    let pubkey_bytes = crate::crypto::address_to_pubkey_bytes(requester)
        .map_err(|_| "invalid requester address".to_string())?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|_| "invalid public key".to_string())?;
    let signature = ed25519_dalek::Signature::from_slice(proof)
        .map_err(|_| "invalid signature format".to_string())?;
    verifying_key.verify_strict(&signed_hash, &signature)
        .map_err(|_| "signature verification failed".to_string())?;

    Ok(())
}

/// Fetch the latest key distribution for a private channel.
fn fetch_private_channel_keys(storage: &Storage, channel_id: u64) -> Vec<Vec<u8>> {
    match storage.get_private_channel_keys_latest(channel_id) {
        Ok(Some((_epoch, key_data))) => vec![key_data],
        Ok(None) => Vec::new(),
        Err(e) => {
            warn!(error = %e, channel_id, "Failed to fetch private channel keys");
            Vec::new()
        }
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
