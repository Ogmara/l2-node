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
        /// klv1... address of the wallet that signed the `anchorState`
        /// TX. In SC v0.3.0+ this is also surfaced as an indexed event
        /// topic; the chain scanner reads it from the TX `sender` since
        /// they are the same value (caller == anchorer) and the scanner
        /// here parses call data, not event topics.
        anchorer: String,
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
    /// Set to `Some(0)` (never a real timestamp — messages that old are
    /// rejected by the ±5min drift check) by the chain scanner on a fresh
    /// on-chain registration, to record "this node has a settled view: no
    /// `ProfileUpdate` has ever been sent for this wallet" — distinct from
    /// `None`, which security-audit finding HIGH-2 (design doc "Closing
    /// the Identity-Sync Coverage Gap") identified as indistinguishable
    /// from "this node hasn't checked/heard yet". Without this, EVERY
    /// on-chain-registered wallet that never sets a display name — the
    /// common case, since registration and profile-setting are separate,
    /// optional actions — looks permanently "incomplete" to
    /// `identity_sync::profile_looks_incomplete_json` and is re-triggered
    /// forever, burning the periodic sweep's entire request budget on
    /// wallets it can never actually fix. A real `MessageType::ProfileUpdate`
    /// (router.rs's apply arm) always writes its own real timestamp here
    /// via `#[serde(flatten)]`-free raw JSON, which — being a real
    /// message timestamp — is always > 0 and correctly overrides this
    /// sentinel under the existing LWW rule (a timestamp <= the stored
    /// value is a no-op). `#[serde(default)]` so a row written before this field
    /// existed still deserializes (as `None` — the pre-existing gap for
    /// ALREADY-stored rows is a known, accepted limitation, not solved by
    /// this field alone; see the design doc for why a broader migration
    /// wasn't judged worth it pre-mainnet).
    ///
    /// **Known, deliberately deferred limitation (re-audit round 2):** the
    /// sentinel cannot distinguish "this wallet has genuinely never sent a
    /// `ProfileUpdate` anywhere" from "this node just hasn't received this
    /// wallet's `ProfileUpdate` yet." If a node's FIRST contact with a
    /// wallet is this scanner discovering its on-chain registration (no
    /// prior gossip contact at all), the sentinel is stamped immediately —
    /// and if that wallet's real `ProfileUpdate` is never independently
    /// gossiped to this node afterward, this node never proactively
    /// re-checks (though a real `ProfileUpdate` is still applied correctly
    /// via LWW if it ever does arrive — nothing is corrupted, it's just
    /// never chased). Not a regression: this specific ordering behaves
    /// identically to pre-0.132.0 (passive-only), since this branch only
    /// runs when no `USERS` row exists yet — a wallet seen via ANY prior
    /// gossip (chat, follow, delegation, or a genuinely-received
    /// `ProfileUpdate`) is unaffected. Closing this fully needs either an
    /// on-chain "has ever set a profile" signal (doesn't exist today) or a
    /// bounded-retry budget per sentinel row — judged disproportionate to a
    /// narrow, non-adversarial edge case for this pass. Revisit if it proves
    /// more common in practice than expected.
    #[serde(default)]
    pub profile_updated_at: Option<u64>,
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

/// `chain::sc_views::get_channel_creator` re-verification bookkeeping for
/// one channel — stored in `storage::schema::cf::CHANNEL_VERIFICATION`,
/// NOT as a field on `ChannelRecord` (audit 2026-09-29). Deliberately kept
/// out of the `CHANNELS` row: that CF is in `snapshot::DOMAIN_CFS` and its
/// raw bytes feed the anchored state root, so a per-node wall-clock
/// verification timestamp inside it would make every node's root for a
/// public channel diverge PERMANENTLY (rewritten with a different value on
/// every independent round-robin re-check), not just transiently — and
/// nothing anchoring-relevant needs to read it anyway.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelVerificationState {
    /// Unix seconds when `creator` was last confirmed against the SC's
    /// `getChannelCreator` view — either by the chain scanner's own
    /// `ChannelCreated`/`ChannelTransferred` processing, or the periodic
    /// `ChainScanner::sweep_channel_verification` re-check. `None` means
    /// never confirmed. A TIMESTAMP, not a bool: the round-robin lane
    /// re-visits already-confirmed channels too, so a transfer whose
    /// on-chain event fell into a permanent scan gap doesn't leave a stale
    /// "verified" standing forever.
    #[serde(default)]
    pub creator_verified_at: Option<u64>,
    /// `true` if the most recent check found the SC has no on-chain record
    /// for this id at all, while the local row claims Public/ReadPublic —
    /// a possible fabricated public-channel claim. Visibility only; no
    /// automatic action taken on this flag.
    #[serde(default)]
    pub creator_verification_failed: bool,
    /// Unix seconds of the last time a `NoOnChainBacking` outcome was
    /// recorded for this id (audit 2026-09-29 round 3.1 — code+security
    /// re-audit of the round-3 sweep). Without this, `sweep_channel_
    /// verification`'s out-of-range lane always starts its scan from the
    /// same lowest out-of-range key, so a handful of standing fabricated-
    /// public-claim rows (an attacker's, or — worse — a legitimate row
    /// mid-on-chain-confirmation) would be re-verified and re-alerted on
    /// EVERY tick forever, burning the whole per-tick RPC budget and
    /// starving the round-robin lane permanently. `verify_one_channel_
    /// creator` skips the RPC entirely while this is within
    /// `NO_BACKING_RECHECK_COOLDOWN_SECS`. Any GENUINE on-chain progress
    /// (the historical scanner actually reaching the real
    /// `ChannelCreated`/`ChannelTransferred` event) bypasses this cooldown
    /// entirely via `mark_channel_creator_verified`, which overwrites this
    /// whole struct directly — so a real confirmation is never delayed by
    /// it, only a repeat negative check is.
    #[serde(default)]
    pub no_backing_checked_at: Option<u64>,
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
    /// klv1... wallet that submitted this anchor (added in v0.43.0 to
    /// support per-anchorer attribution alongside the SC v0.3.0 quorum
    /// model). Older records persisted before the upgrade may carry
    /// an empty string here — readers must handle that case.
    #[serde(default)]
    pub anchorer: String,
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
