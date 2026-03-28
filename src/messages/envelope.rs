//! Message envelope — the universal wrapper for all Ogmara protocol messages.
//!
//! Every piece of data in the network is wrapped in an Envelope (spec 3.1).
//! Provides uniform structure for routing, verification, and storage.

use serde::{Deserialize, Serialize};

use super::types::MessageType;

/// The standard message envelope (spec 3.1).
///
/// All messages in the Ogmara network are wrapped in this structure.
/// The payload is stored as raw MessagePack bytes — deserialized to a
/// typed payload based on `msg_type` when needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version (currently 1).
    pub version: u8,
    /// Message type identifier.
    pub msg_type: MessageType,
    /// Keccak-256(author_pubkey_bytes + payload_bytes + timestamp_bytes).
    pub msg_id: [u8; 32],
    /// Sender's Klever address (klv1...).
    pub author: String,
    /// Unix timestamp in milliseconds.
    pub timestamp: u64,
    /// Lamport clock for causal ordering (spec 7.2).
    pub lamport_ts: u64,
    /// MessagePack-serialized payload bytes.
    pub payload: Vec<u8>,
    /// Ed25519 signature (must be exactly 64 bytes).
    pub signature: Vec<u8>,
    /// Nodes that relayed this message (not signed, appended during relay).
    #[serde(default)]
    pub relay_path: Vec<String>,
}

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum allowed clock drift for message timestamps (±5 minutes in ms).
pub const MAX_TIMESTAMP_DRIFT_MS: u64 = 5 * 60 * 1000;

impl Envelope {
    /// Serialize this envelope to MessagePack bytes for storage or transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        rmp_serde::to_vec(self)
    }

    /// Deserialize an envelope from MessagePack bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(data)
    }

    /// Check if the timestamp is within acceptable drift of the given reference time.
    pub fn is_timestamp_valid(&self, reference_time_ms: u64) -> bool {
        let diff = if self.timestamp > reference_time_ms {
            self.timestamp - reference_time_ms
        } else {
            reference_time_ms - self.timestamp
        };
        diff <= MAX_TIMESTAMP_DRIFT_MS
    }

    /// Get the message type as a u8 for signature computation.
    pub fn msg_type_u8(&self) -> u8 {
        self.msg_type as u8
    }

    /// Validate basic envelope structure (signature length, version, relay_path).
    pub fn validate_structure(&self) -> Result<(), &'static str> {
        if self.signature.len() != 64 {
            return Err("signature must be exactly 64 bytes");
        }
        if self.version == 0 {
            return Err("version must be > 0");
        }
        // Limit relay path to prevent amplification
        if self.relay_path.len() > 64 {
            return Err("relay_path exceeds maximum length");
        }
        Ok(())
    }
}
