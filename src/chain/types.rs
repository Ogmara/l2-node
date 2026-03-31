//! On-chain data types for the Klever chain scanner.
//!
//! Represents SC events and local state derived from on-chain data
//! (spec 02-onchain.md section 6).

use serde::{Deserialize, Serialize};

/// Smart contract events emitted by the Ogmara KApp.
///
/// L2 nodes monitor these events to build local state (spec 6.2).
#[derive(Debug, Clone)]
pub enum ScEvent {
    UserRegistered {
        address: String,
        public_key: String,
        timestamp: u64,
    },
    PublicKeyUpdated {
        address: String,
        public_key: String,
    },
    ChannelCreated {
        channel_id: u64,
        creator: String,
        slug: String,
        channel_type: u8,
        timestamp: u64,
    },
    ChannelTransferred {
        channel_id: u64,
        from: String,
        to: String,
    },
    DeviceDelegated {
        user: String,
        device_key: String,
        permissions: u8,
        expires_at: u64,
        timestamp: u64,
    },
    DeviceRevoked {
        user: String,
        device_key: String,
        timestamp: u64,
    },
    StateAnchored {
        block_height: u64,
        state_root: String,
        message_count: u64,
        channel_count: u32,
        user_count: u32,
        node_id: String,
        timestamp: u64,
    },
    TipSent {
        sender: String,
        recipient: String,
        amount: u64,
        msg_id: String,
        channel_id: u64,
        note: String,
        timestamp: u64,
    },
}

/// Local user state cached from on-chain registration events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    /// Klever address (klv1...).
    pub address: String,
    /// Ed25519 public key (hex-encoded, 64 chars).
    pub public_key: String,
    /// Registration timestamp from SC event.
    pub registered_at: u64,
    /// Display name (from L2 ProfileUpdate, not on-chain).
    pub display_name: Option<String>,
    /// Avatar IPFS CID (from L2 ProfileUpdate).
    pub avatar_cid: Option<String>,
    /// Bio (from L2 ProfileUpdate).
    pub bio: Option<String>,
}

/// Local channel state cached from on-chain events + L2 updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelRecord {
    /// SC-assigned sequential channel ID.
    pub channel_id: u64,
    /// Unique slug (from SC).
    pub slug: String,
    /// Creator address (from SC).
    pub creator: String,
    /// Channel type: 0=Public, 1=ReadPublic.
    pub channel_type: u8,
    /// Creation timestamp (from SC).
    pub created_at: u64,
    /// Display name (from L2 ChannelUpdate, not on-chain).
    pub display_name: Option<String>,
    /// Description (from L2 ChannelUpdate, not on-chain).
    pub description: Option<String>,
    /// Member count (tracked by L2 node).
    pub member_count: u64,
}

/// Local delegation state cached from on-chain events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRecord {
    /// User who delegated.
    pub user_address: String,
    /// Device Ed25519 public key (hex-encoded).
    pub device_pub_key: String,
    /// Permission bitmask: 0x01=messages, 0x02=channels, 0x04=profile.
    pub permissions: u8,
    /// Expiration timestamp (0 = no expiry).
    pub expires_at: u64,
    /// When the delegation was created.
    pub created_at: u64,
    /// Whether this delegation is currently active.
    pub active: bool,
}

/// State anchor record from on-chain anchoring events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateAnchorRecord {
    pub block_height: u64,
    pub state_root: String,
    pub message_count: u64,
    pub channel_count: u32,
    pub user_count: u32,
    pub node_id: String,
    pub anchored_at: u64,
}

/// A Klever transaction from the API transaction list.
///
/// The Klever API returns SC calls with the function name and arguments
/// hex-encoded in the `data` field, and the contract address in
/// `contract[0].parameter.address`.
#[derive(Debug, Clone, Deserialize)]
pub struct KleverTransaction {
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub sender: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, rename = "blockNum")]
    pub block_num: u64,
    #[serde(default)]
    pub timestamp: u64,
    /// SC call data: hex-encoded "functionName@arg1@arg2".
    #[serde(default)]
    pub data: Vec<String>,
    /// Contract invocation details.
    #[serde(default)]
    pub contract: Vec<KleverContractCall>,
}

/// A contract call entry within a Klever transaction.
#[derive(Debug, Clone, Deserialize)]
pub struct KleverContractCall {
    /// Transaction type (63 = SmartContract).
    #[serde(default, rename = "type")]
    pub tx_type: u32,
    #[serde(default)]
    pub parameter: KleverContractParam,
}

/// Parameters of a contract call.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct KleverContractParam {
    /// Target contract address (klv1...).
    #[serde(default)]
    pub address: String,
    /// "SCDeploy", "SCInvoke", etc.
    #[serde(default, rename = "type")]
    pub call_type: String,
}
