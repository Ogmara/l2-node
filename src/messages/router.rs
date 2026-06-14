//! Message routing pipeline (spec 3.4).
//!
//! Processing steps for every incoming message:
//! 1. Deserialize (MessagePack)
//! 2. Validate envelope (version, msg_type, msg_id, signature length)
//! 3. Check duplicate (msg_id lookup in storage)
//! 4. Verify signature (Ed25519, check delegation if needed)
//! 5. Verify timestamp (±5 min drift)
//! 6. Check rate limits (per-user counters)
//! 7. Validate payload (type-specific rules)
//! 8. Store message (RocksDB)
//! 9. Forward to GossipSub (relay to peers)
//! 10. Notify local clients (WebSocket push)
//! 11. Check mention notifications

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use dashmap::DashMap;
use tracing::{debug, warn};

use crate::crypto;
use crate::crypto::signing;
use crate::storage::identity::IdentityResolver;
use crate::storage::rocks::Storage;
use crate::storage::schema;
use ed25519_dalek;

use super::envelope::Envelope;
use super::types::*;
use super::validation;

/// Per-user, per-category rate limit counters.
struct RateLimitEntry {
    /// Message count in the current window.
    count: u32,
    /// Window start (Unix ms).
    window_start: u64,
}

/// Rate limit categories with per-spec limits (spec Part 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RateCategory {
    ChatMessages,      // 30 per minute
    NewsPost,          // 5 per hour
    Reaction,          // 60 per minute (chat + news reactions)
    Repost,            // 10 per hour
    ChannelAdmin,      // 30 per hour (kick/ban/mute)
    ModeratorChange,   // 10 per day
    ChannelInvite,     // 20 per hour
    PinUnpin,          // 20 per hour
    Other,             // fallback: 100 per minute
}

impl RateCategory {
    /// (max_count, window_ms) per category.
    fn limits(self) -> (u32, u64) {
        match self {
            Self::ChatMessages => (30, 60_000),
            Self::NewsPost => (5, 3_600_000),
            Self::Reaction => (60, 60_000),
            Self::Repost => (10, 3_600_000),
            Self::ChannelAdmin => (30, 3_600_000),
            Self::ModeratorChange => (10, 86_400_000),
            Self::ChannelInvite => (20, 3_600_000),
            Self::PinUnpin => (20, 3_600_000),
            Self::Other => (100, 60_000),
        }
    }

    fn from_msg_type(msg_type: MessageType) -> Self {
        match msg_type {
            MessageType::ChatMessage | MessageType::ChatEdit | MessageType::ChatDelete
            | MessageType::DirectMessage | MessageType::DirectMessageEdit
            | MessageType::DirectMessageDelete => Self::ChatMessages,
            MessageType::NewsPost | MessageType::NewsEdit | MessageType::NewsDelete
            | MessageType::NewsComment => Self::NewsPost,
            MessageType::ChatReaction | MessageType::DirectMessageReaction
            | MessageType::NewsReaction => Self::Reaction,
            MessageType::NewsRepost => Self::Repost,
            MessageType::ChannelKick | MessageType::ChannelBan
            | MessageType::ChannelUnban | MessageType::ChannelMute => Self::ChannelAdmin,
            MessageType::ChannelAddModerator | MessageType::ChannelRemoveModerator
            | MessageType::PrivateChannelKeyDistribution => Self::ModeratorChange,
            MessageType::ChannelInvite => Self::ChannelInvite,
            MessageType::ChannelPinMessage | MessageType::ChannelUnpinMessage => Self::PinUnpin,
            _ => Self::Other,
        }
    }
}

/// Max active encryption keys retained per wallet (protocol §2.4). Bounds the
/// `device_enc_keys` directory and the multi-device wrap fan-out.
const MAX_ENC_KEYS_PER_WALLET: usize = 10;

/// Max per-device key envelopes retained per `key_scope` (all targets/devices/
/// epochs). Bounds the `channel_keys` CF against a flood of envelopes addressed to
/// fabricated device ids (spec 8.1.1). Generous: covers many devices × retained
/// history epochs for a DM or channel.
const MAX_CHANNEL_KEY_ENVELOPES_PER_SCOPE: usize = 4096;

/// The message router processes incoming messages through the full pipeline.
pub struct MessageRouter {
    storage: Storage,
    /// Device-to-wallet identity resolver.
    identity: IdentityResolver,
    /// Per-user, per-category rate limit counters: "(address:category)" → entry.
    rate_limits: DashMap<String, RateLimitEntry>,
    /// PoW anti-spam manager (None = PoW disabled).
    pow: Option<Arc<crate::pow::PowManager>>,
}

/// Result of processing a message through the router.
#[derive(Debug)]
pub enum RouteResult {
    /// Message accepted, stored, and should be relayed.
    Accepted {
        msg_id: [u8; 32],
        msg_type: MessageType,
        /// Raw envelope bytes for downstream processing (notifications, etc.).
        raw_bytes: Vec<u8>,
    },
    /// Message is a duplicate (already stored).
    Duplicate,
    /// Message rejected on a POLICY/authz/local basis (e.g. banned user,
    /// unknown channel, storage error). The envelope is structurally sound and
    /// an honest peer may legitimately relay it, so over gossip this maps to
    /// `Ignore` (don't propagate from us, but don't penalize the relaying peer).
    Rejected(String),
    /// Message is cryptographically/structurally INVALID (bad signature,
    /// malformed envelope, wrong msg_id) — no honest peer should be relaying it.
    /// Over gossip this maps to `Reject` so gossipsub penalizes the source
    /// (audit 2026-06-07 W6). The API layer treats it like `Rejected` (400).
    Invalid(String),
    /// Message rejected because the wallet needs to solve a PoW challenge first.
    /// The API layer converts this to a 429 response with the challenge payload.
    PowRequired {
        /// The wallet address that needs to solve the challenge.
        address: String,
    },
}

impl MessageRouter {
    pub fn new(
        storage: Storage,
        identity: IdentityResolver,
        pow: Option<Arc<crate::pow::PowManager>>,
    ) -> Self {
        Self {
            storage,
            identity,
            rate_limits: DashMap::new(),
            pow,
        }
    }

    /// Process a raw message through the full pipeline.
    ///
    /// Returns the routing result indicating whether the message was
    /// accepted, is a duplicate, or was rejected.
    pub fn process_message(&self, raw_bytes: &[u8]) -> RouteResult {
        self.process_message_inner(raw_bytes, false)
    }

    /// Process a synced historical message — skips timestamp drift and rate limiting.
    ///
    /// Used for messages received via the sync protocol, which are intentionally
    /// older than the 5-minute drift window. All other validation (signature,
    /// identity, payload, dedup) still applies.
    pub fn process_synced_message(&self, raw_bytes: &[u8]) -> RouteResult {
        self.process_message_inner(raw_bytes, true)
    }

    fn process_message_inner(&self, raw_bytes: &[u8], is_sync: bool) -> RouteResult {
        // Step 1: Deserialize
        let envelope: Envelope = match rmp_serde::from_slice(raw_bytes) {
            Ok(env) => env,
            Err(e) => return RouteResult::Invalid(format!("deserialization failed: {}", e)),
        };

        // Step 2: Validate envelope structure
        if let Err(e) = envelope.validate_structure() {
            return RouteResult::Invalid(format!("invalid envelope: {}", e));
        }

        // Step 3: Check duplicate
        match self.storage.message_exists(&envelope.msg_id) {
            Ok(true) => return RouteResult::Duplicate,
            Ok(false) => {}
            Err(e) => return RouteResult::Rejected(format!("storage error: {}", e)),
        }

        // Step 4a: Verify msg_id computation
        if let Err(e) = self.verify_msg_id(&envelope) {
            return RouteResult::Invalid(format!("invalid msg_id: {}", e));
        }

        // Step 4b: Verify Ed25519 signature (against device/signing key)
        if let Err(e) = self.verify_signature(&envelope) {
            return RouteResult::Invalid(format!("signature verification failed: {}", e));
        }

        // Step 4c: Resolve device key → wallet address for all subsequent operations.
        // Signature verification used envelope.author (device key) directly.
        // From here on, `resolved_author` is the wallet identity used for
        // storage, indexing, rate limiting, and authorization.
        let resolved_author = match self.identity.resolve(&envelope.author) {
            Ok(addr) => addr,
            Err(e) => return RouteResult::Rejected(format!("identity resolution failed: {}", e)),
        };

        // Device enc-key bindings MUST be authored directly by the WALLET (protocol
        // §2.4): the wallet's `signMessage` over the canonical claim is the sole
        // authority. Reject a delegated device authoring one — otherwise a single
        // delegated device could poison the wallet's enc-key directory (audit
        // WARNING-2), causing senders to encrypt to an attacker-controlled key.
        if matches!(
            envelope.msg_type,
            MessageType::DeviceEncBinding | MessageType::DeviceEncRevoke
        ) && envelope.author != resolved_author
        {
            return RouteResult::Rejected(
                "enc-key binding/revoke must be authored by the wallet itself".into(),
            );
        }

        // Step 4d: Tiered identity requirements.
        //
        // Basic messages (chat, news posts, reactions, follows, etc.) are allowed
        // for any wallet with a valid signature — no on-chain registration needed.
        //
        // Advanced messages (edits, deletes, channel management, moderation, private
        // channels) require a verified identity: on-chain registration via the SC,
        // indicated by `registered_at > 0` in the USERS record.
        //
        // DeviceDelegation is always exempt (it establishes the mapping itself).
        // The check uses `resolved_author` (the wallet identity) regardless of
        // whether a device mapping exists — extension/K5 users must also have
        // on-chain registration for advanced features.
        if envelope.msg_type != MessageType::DeviceDelegation
            && envelope.msg_type.requires_verified_identity()
        {
            match self.storage.get_cf(
                crate::storage::schema::cf::USERS,
                resolved_author.as_bytes(),
            ) {
                Ok(Some(data)) => {
                    // User exists — check if on-chain registered (registered_at > 0
                    // means the chain scanner wrote this, not just a ProfileUpdate).
                    let is_verified = serde_json::from_slice::<serde_json::Value>(&data)
                        .ok()
                        .and_then(|v| v.get("registered_at")?.as_u64())
                        .map_or(false, |ts| ts > 0);
                    if !is_verified {
                        return RouteResult::Rejected(
                            "on-chain registration required: verify your wallet to use this feature".into(),
                        );
                    }
                }
                _ => {
                    return RouteResult::Rejected(
                        "on-chain registration required: verify your wallet to use this feature".into(),
                    );
                }
            }
        }

        // Step 4e: Proof-of-Work gate for unknown wallets.
        //
        // Wallets that are on-chain registered (checked in 4d) or already known
        // (solved PoW before, persisted in KNOWN_WALLETS CF) skip this check.
        // DeviceDelegation is always exempt (it establishes the device mapping).
        // Network messages are exempt. Synced historical messages are exempt.
        if !is_sync
            && envelope.msg_type != MessageType::DeviceDelegation
            && envelope.msg_type.requires_registration()
        {
            if let Some(ref pow) = self.pow {
                // Skip if wallet already passed the on-chain registration check above
                // (requires_verified_identity returned true and check passed).
                // For basic messages (chat, news, etc.), check PoW requirement.
                let needs_pow = if envelope.msg_type.requires_verified_identity() {
                    // Already verified on-chain above — if we got here, they're registered
                    false
                } else {
                    !pow.is_wallet_known(&resolved_author)
                };

                if needs_pow {
                    return RouteResult::PowRequired {
                        address: resolved_author,
                    };
                }
            }
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Step 5: Verify timestamp (±5 min drift) — skipped for synced historical messages
        if !is_sync && !envelope.is_timestamp_valid(now_ms) {
            return RouteResult::Rejected(format!(
                "timestamp drift too large: {} vs now {}",
                envelope.timestamp, now_ms
            ));
        }

        // Step 6: Rate limit by wallet address — skipped for synced messages
        if !is_sync && envelope.msg_type.requires_registration() {
            let category = RateCategory::from_msg_type(envelope.msg_type);
            if self.is_rate_limited(&resolved_author, category, now_ms) {
                return RouteResult::Rejected(format!("rate limited ({:?})", category));
            }
        }

        // Step 7: Validate payload (type-specific rules — uses resolved author)
        if let Err(e) = self.validate_payload(&envelope, &resolved_author) {
            return RouteResult::Rejected(format!("payload validation failed: {}", e));
        }

        // Step 7b: Check ban enforcement — banned users cannot post to channels
        if let Err(e) = self.check_channel_ban(&envelope, &resolved_author) {
            return RouteResult::Rejected(format!("banned: {}", e));
        }

        // Step 7b2: Check mute enforcement — muted users cannot send messages/reactions
        if let Err(e) = self.check_channel_mute(&envelope, &resolved_author) {
            return RouteResult::Rejected(format!("muted: {}", e));
        }

        // Step 7c: Authorize channel admin operations
        if let Err(e) = self.authorize_channel_action(&envelope, &resolved_author) {
            return RouteResult::Rejected(format!("unauthorized: {}", e));
        }

        // Step 7d: Authorize edit/delete operations — author must match original, edits have 30-min window
        if let Err(e) = self.authorize_edit_delete(&envelope, &resolved_author, now_ms) {
            return RouteResult::Rejected(format!("edit/delete denied: {}", e));
        }

        // Step 7e: Read-only / broadcast channel enforcement — only creator and
        // moderators can post ChatMessage / ChatEdit / ChatDelete in ReadPublic
        // channels. Reactions remain open to all members. See protocol spec §3.6.
        if let Err(e) = self.check_readonly_channel(&envelope, &resolved_author) {
            return RouteResult::Rejected(format!("broadcast_channel_post_denied: {}", e));
        }

        // Step 8: Store message (atomically increments total_messages counter)
        if let Err(e) = self.storage.store_message(&envelope.msg_id, raw_bytes) {
            return RouteResult::Rejected(format!("storage error: {}", e));
        }

        // Step 8b: Update indexes using resolved wallet address
        if let Err(e) = self.update_indexes(&envelope, &resolved_author) {
            warn!(error = %e, "Failed to update indexes (message still stored)");
        }

        // After first successful message from a basic (non-registered) wallet,
        // mark them as known so future PoW checks are skipped (persists across restarts).
        // Only needed for message types subject to PoW (step 4e).
        if let Some(ref pow) = self.pow {
            if !is_sync
                && envelope.msg_type != MessageType::DeviceDelegation
                && envelope.msg_type.requires_registration()
                && !envelope.msg_type.requires_verified_identity()
            {
                pow.mark_wallet_known(&resolved_author);
            }
        }

        debug!(
            msg_id = %hex::encode(envelope.msg_id),
            msg_type = ?envelope.msg_type,
            signing_key = %envelope.author,
            author = %resolved_author,
            "Message routed successfully"
        );

        // Steps 9-11 (relay, WS push, notifications) are handled by the caller
        RouteResult::Accepted {
            msg_id: envelope.msg_id,
            msg_type: envelope.msg_type,
            raw_bytes: raw_bytes.to_vec(),
        }
    }

    /// Verify the Ed25519 signature on the envelope.
    ///
    /// Supports both Ogmara protocol signing (delegated/device keys) and
    /// Klever message signing (wallet keys). Tries Ogmara format first.
    fn verify_signature(&self, envelope: &Envelope) -> Result<()> {
        let verifying_key = crypto::address_to_verifying_key(&envelope.author)
            .map_err(|e| anyhow::anyhow!("invalid author key: {}", e))?;

        let signature = ed25519_dalek::Signature::from_slice(&envelope.signature)
            .map_err(|e| anyhow::anyhow!("invalid signature bytes: {}", e))?;

        // DeviceDelegation is dual-signed over the CLAIM string, not the
        // binary envelope preimage (P-0, l2-node 0.49.0+). Browser-extension
        // wallets can only sign UTF-8 strings (`signMessage`), so the wallet
        // authorizes via a Klever-format signature over the canonical claim;
        // the DEVICE key co-signs the SAME claim as proof-of-possession. We
        // verify BOTH here at the gate so a forged/tampered delegation is
        // rejected before it is stored or relayed (process_message order:
        // verify → store → apply → caller relays). This makes the binding
        // unforgeable: impersonating a wallet needs the wallet key; hijacking
        // a device needs the device key.
        if envelope.msg_type == MessageType::DeviceDelegation {
            return self.verify_device_delegation_claim(envelope, &verifying_key, &signature);
        }

        // DeviceEncBinding / DeviceEncRevoke are wallet-authorized over a canonical
        // claim string (browser/K5 wallets can only `signMessage`), same shape as
        // DeviceDelegation minus the device co-sign (an X25519 enc key cannot sign).
        if matches!(
            envelope.msg_type,
            MessageType::DeviceEncBinding | MessageType::DeviceEncRevoke
        ) {
            return self.verify_device_enc_claim(envelope, &verifying_key, &signature);
        }

        // Try Ogmara protocol format first (most common for L2 messages)
        let ogmara_result = signing::verify_ogmara_message(
            &verifying_key,
            envelope.version,
            envelope.msg_type_u8(),
            &envelope.msg_id,
            envelope.timestamp,
            &envelope.payload,
            &signature,
        );

        if ogmara_result.is_ok() {
            return Ok(());
        }

        // Fall back to Klever message format (for wallet-signed messages)
        let signed_bytes = signing::ogmara_signed_bytes(
            envelope.version,
            envelope.msg_type_u8(),
            &envelope.msg_id,
            envelope.timestamp,
            &envelope.payload,
        );
        let klever_result = signing::verify_klever_message(
            &verifying_key,
            &signed_bytes,
            &signature,
        );

        klever_result.map_err(|_| {
            anyhow::anyhow!(
                "signature verification failed for both formats (author={}, msg_type={:?}, ts={}, payload_len={}, sig_len={})",
                envelope.author,
                envelope.msg_type,
                envelope.timestamp,
                envelope.payload.len(),
                envelope.signature.len(),
            )
        })
    }

    /// Dual-signature verification for a `DeviceDelegation` envelope (P-0).
    ///
    /// Both the WALLET (authorizes the binding) and the DEVICE (proves it
    /// holds the key) must have signed the canonical claim string
    /// `ogmara-device-claim:{device_pub_key_lowercase}:{wallet}:{timestamp}`
    /// in Klever message format:
    ///   * `envelope.signature` — the wallet's signature, checked against
    ///     `envelope.author` (the wallet `wallet_key`).
    ///   * `payload.device_signature` — the device's signature, checked
    ///     against the device public key in the payload.
    ///
    /// A relaying node is never trusted: a receiver re-derives the claim from
    /// the envelope and re-verifies both signatures, so it cannot be tricked
    /// into storing a binding the wallet didn't authorize or the device
    /// doesn't control.
    fn verify_device_delegation_claim(
        &self,
        envelope: &Envelope,
        wallet_key: &ed25519_dalek::VerifyingKey,
        wallet_sig: &ed25519_dalek::Signature,
    ) -> Result<()> {
        let payload: DeviceDelegationPayload =
            rmp_serde::from_slice(&envelope.payload)
                .context("DeviceDelegation payload decode for signature verification")?;

        // Canonical claim string — lowercase device pubkey so the bytes the
        // two signers signed are reproduced exactly on every node.
        let device_pubkey_hex = payload.device_pub_key.to_ascii_lowercase();
        let claim = format!(
            "ogmara-device-claim:{}:{}:{}",
            device_pubkey_hex, envelope.author, envelope.timestamp
        );

        // 1) Wallet authorizes the binding.
        signing::verify_klever_message(wallet_key, claim.as_bytes(), wallet_sig)
            .map_err(|_| anyhow::anyhow!("DeviceDelegation wallet claim signature invalid"))?;

        // 2) Device proves possession of its key over the SAME claim.
        let dev_pubkey_bytes: [u8; 32] = hex::decode(&device_pubkey_hex)
            .context("device_pub_key hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("device_pub_key must be 32 bytes"))?;
        let dev_key = ed25519_dalek::VerifyingKey::from_bytes(&dev_pubkey_bytes)
            .map_err(|e| anyhow::anyhow!("invalid device public key: {}", e))?;
        let dev_sig_bytes = hex::decode(&payload.device_signature)
            .map_err(|_| anyhow::anyhow!("device_signature is not valid hex"))?;
        let dev_sig = ed25519_dalek::Signature::from_slice(&dev_sig_bytes)
            .map_err(|_| anyhow::anyhow!("device_signature must be 64 bytes"))?;
        signing::verify_klever_message(&dev_key, claim.as_bytes(), &dev_sig)
            .map_err(|_| anyhow::anyhow!("DeviceDelegation device proof-of-possession invalid"))?;

        // The signed claim covers only the device↔wallet↔timestamp binding —
        // NOT `permissions`/`expires_at`. To stop a relaying node from forging
        // those fields (recomputing msg_id and riding the genuine claim
        // signatures), require the canonical values at the gate. Device→wallet
        // resolution ignores permissions today, but enforcing the canonical
        // form here removes the forgery surface entirely and keeps a future
        // code path from ever trusting relay-supplied permissions. The node's
        // own builder (`build_and_gossip_dual_delegation`) always emits exactly
        // these values. Granular/expiring delegations, if ever needed, must
        // bring permissions+expiry under the signature (P-2+).
        if !(payload.permissions.can_send_messages
            && payload.permissions.can_create_channels
            && payload.permissions.can_update_profile)
            || payload.expires_at.is_some()
        {
            anyhow::bail!(
                "DeviceDelegation must carry canonical permissions and no expiry \
                 (unsigned fields; rejected to prevent relay forgery)"
            );
        }

        Ok(())
    }

    /// Verify a `DeviceEncBinding` / `DeviceEncRevoke` envelope (P0 E2E).
    ///
    /// The envelope is authored by the WALLET; `envelope.signature` is the wallet's
    /// Klever-message signature over a canonical claim re-derived from envelope
    /// fields (protocol §2.4), so a relaying node cannot forge it:
    ///   * bind:   `ogmara-enc-bind:{enc_pub_lc}:{device_id_lc}:{wallet}:{timestamp}`
    ///   * revoke: `ogmara-enc-revoke:{enc_pub_lc}:{wallet}:{timestamp}`
    /// No device co-signature: an X25519 encryption key cannot produce a signature,
    /// and the wallet signature is the sole authority (binding a key the wallet does
    /// not control only harms that wallet).
    fn verify_device_enc_claim(
        &self,
        envelope: &Envelope,
        wallet_key: &ed25519_dalek::VerifyingKey,
        wallet_sig: &ed25519_dalek::Signature,
    ) -> Result<()> {
        let claim = match envelope.msg_type {
            MessageType::DeviceEncBinding => {
                let p: DeviceEncBindingPayload = rmp_serde::from_slice(&envelope.payload)
                    .context("DeviceEncBinding payload decode for signature verification")?;
                Self::validate_hex32(&p.enc_pub, "enc_pub")?;
                Self::validate_hex32(&p.device_id, "device_id")?;
                format!(
                    "ogmara-enc-bind:{}:{}:{}:{}",
                    p.enc_pub.to_ascii_lowercase(),
                    p.device_id.to_ascii_lowercase(),
                    envelope.author,
                    envelope.timestamp
                )
            }
            MessageType::DeviceEncRevoke => {
                let p: DeviceEncRevokePayload = rmp_serde::from_slice(&envelope.payload)
                    .context("DeviceEncRevoke payload decode for signature verification")?;
                Self::validate_hex32(&p.enc_pub, "enc_pub")?;
                format!(
                    "ogmara-enc-revoke:{}:{}:{}",
                    p.enc_pub.to_ascii_lowercase(),
                    envelope.author,
                    envelope.timestamp
                )
            }
            _ => unreachable!("verify_device_enc_claim called for non-enc message type"),
        };

        signing::verify_klever_message(wallet_key, claim.as_bytes(), wallet_sig)
            .map_err(|_| anyhow::anyhow!("DeviceEnc wallet claim signature invalid"))
    }

    /// Validate a hex string decodes to exactly 32 bytes (Ed25519/X25519 key).
    fn validate_hex32(s: &str, field: &str) -> Result<()> {
        let bytes = hex::decode(s).map_err(|_| anyhow::anyhow!("{} is not valid hex", field))?;
        if bytes.len() != 32 {
            anyhow::bail!("{} must be 32 bytes", field);
        }
        Ok(())
    }

    /// True if an incoming enc-key op at `ts` is strictly newer than the existing
    /// record for `key` (last-write-wins; an absent record counts as newer). This
    /// is what prevents a replayed/stale bind or revoke from overwriting newer
    /// state or resurrecting a revocation tombstone.
    fn enc_key_is_newer(&self, key: &[u8], ts: u64) -> Result<bool> {
        let existing_ts = self
            .storage
            .get_cf(schema::cf::DEVICE_ENC_KEYS, key)?
            .and_then(|v| serde_json::from_slice::<serde_json::Value>(&v).ok())
            .and_then(|r| r.get("ts").and_then(|t| t.as_u64()));
        Ok(existing_ts.map_or(true, |existing| ts > existing))
    }

    /// Count active (non-revoked, non-tombstoned) enc keys for a wallet, excluding
    /// `skip_enc_pub` so re-binding an existing key is not counted against the cap.
    fn count_active_enc_keys(&self, wallet: &str, skip_enc_pub: &str) -> Result<usize> {
        let mut prefix = wallet.as_bytes().to_vec();
        prefix.push(0xFF);
        let entries = self
            .storage
            .prefix_iter_cf(schema::cf::DEVICE_ENC_KEYS, &prefix, 256)?;
        let count = entries
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice::<serde_json::Value>(&v).ok())
            .filter(|r| {
                let revoked = r.get("revoked").and_then(|b| b.as_bool()).unwrap_or(false);
                let ep = r.get("enc_pub").and_then(|s| s.as_str()).unwrap_or("");
                !revoked && ep != skip_enc_pub
            })
            .count();
        Ok(count)
    }

    /// Enforce one active `enc_pub` per `(wallet, device_id)` at bind time
    /// (protocol §2.4). Scans the wallet's enc-key directory for OTHER active keys
    /// bound to the same `device_id` and returns a supersede plan:
    ///   - `newer_exists`: an active key for this device already has `ts >= ts`, so
    ///     the incoming binding lost the last-write-wins race and must itself be
    ///     stored as a revoked tombstone (a later replay can't resurrect it active).
    ///   - `to_revoke`: directory keys of strictly-older active device keys to
    ///     tombstone so the directory serves exactly one active `enc_pub` per device.
    ///
    /// An empty `device_id` yields an empty plan — without a device identity we
    /// cannot tell which prior keys belong to the same device, so we never supersede
    /// (the per-wallet cap remains the only bound). The `>= ts` tie-break keeps the
    /// already-stored key on an exact timestamp collision; this converges across
    /// gossip replays because every node applies the same highest-ts-wins rule.
    fn plan_enc_key_supersede(
        &self,
        wallet: &str,
        device_id: &str,
        keep_enc_pub: &str,
        ts: u64,
    ) -> Result<(bool, Vec<(Vec<u8>, String)>)> {
        if device_id.is_empty() {
            return Ok((false, Vec::new()));
        }
        let mut prefix = wallet.as_bytes().to_vec();
        prefix.push(0xFF);
        let entries = self
            .storage
            .prefix_iter_cf(schema::cf::DEVICE_ENC_KEYS, &prefix, 256)?;
        let mut newer_exists = false;
        let mut to_revoke = Vec::new();
        for (k, v) in entries {
            let r = match serde_json::from_slice::<serde_json::Value>(&v) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if r.get("revoked").and_then(|b| b.as_bool()).unwrap_or(false) {
                continue;
            }
            let r_dev = r.get("device_id").and_then(|s| s.as_str()).unwrap_or("");
            let r_enc = r.get("enc_pub").and_then(|s| s.as_str()).unwrap_or("");
            // Only collide with the SAME device's OTHER enc keys.
            if r_dev.is_empty() || r_dev != device_id || r_enc == keep_enc_pub {
                continue;
            }
            let r_ts = r.get("ts").and_then(|t| t.as_u64()).unwrap_or(0);
            if r_ts >= ts {
                newer_exists = true;
            } else {
                to_revoke.push((k, r_enc.to_string()));
            }
        }
        Ok((newer_exists, to_revoke))
    }

    /// Verify that the msg_id matches Keccak-256(author + payload + timestamp).
    fn verify_msg_id(&self, envelope: &Envelope) -> Result<()> {
        let author_bytes = crypto::address_to_pubkey_bytes(&envelope.author)
            .map_err(|e| anyhow::anyhow!("invalid author address: {}", e))?;

        let computed = crypto::compute_msg_id(
            &author_bytes,
            &envelope.payload,
            envelope.timestamp,
        );

        if computed != envelope.msg_id {
            anyhow::bail!(
                "msg_id mismatch: expected {}, got {}",
                hex::encode(computed),
                hex::encode(envelope.msg_id)
            );
        }
        Ok(())
    }

    /// Check if a user is rate-limited for a specific action category.
    fn is_rate_limited(&self, author: &str, category: RateCategory, now_ms: u64) -> bool {
        let (max_count, window_ms) = category.limits();
        let key = format!("{}:{:?}", author, category);

        let mut entry = self
            .rate_limits
            .entry(key)
            .or_insert(RateLimitEntry {
                count: 0,
                window_start: now_ms,
            });

        // Reset window if expired
        if now_ms.saturating_sub(entry.window_start) > window_ms {
            entry.count = 0;
            entry.window_start = now_ms;
        }

        entry.count = entry.count.saturating_add(1);
        entry.count > max_count
    }

    /// Evict expired rate limit entries to prevent unbounded memory growth.
    /// Should be called periodically (e.g., every few minutes).
    pub fn cleanup_rate_limits(&self) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Use the largest window (86_400_000ms = 1 day) as the eviction threshold
        self.rate_limits.retain(|_, entry| {
            now_ms.saturating_sub(entry.window_start) < 86_400_000
        });
    }

    /// Validate the payload based on message type.
    fn validate_payload(&self, envelope: &Envelope, resolved_author: &str) -> Result<(), validation::ValidationError> {
        match deserialize_payload(envelope.msg_type, &envelope.payload) {
            Ok(payload) => match payload {
                DeserializedPayload::ChatMessage(ref p) => validation::validate_chat_message(p),
                DeserializedPayload::NewsPost(ref p) => validation::validate_news_post(p),
                DeserializedPayload::NewsComment(ref p) => validation::validate_news_comment(p),
                DeserializedPayload::ChannelCreate(ref p) => validation::validate_channel_create(p),
                DeserializedPayload::ChannelUpdate(ref p) => validation::validate_channel_update(p),
                DeserializedPayload::ProfileUpdate(ref p) => validation::validate_profile_update(p),
                DeserializedPayload::Edit(ref p) => match envelope.msg_type {
                    MessageType::ChatEdit => validation::validate_chat_edit(p),
                    MessageType::DirectMessageEdit => validation::validate_dm_edit(p),
                    MessageType::NewsEdit => validation::validate_news_edit(p),
                    _ => validation::validate_edit(p),
                },
                DeserializedPayload::Delete(ref p) => match envelope.msg_type {
                    MessageType::ChatDelete => validation::validate_chat_delete(p),
                    MessageType::DirectMessageDelete => validation::validate_dm_delete(p),
                    MessageType::NewsDelete => validation::validate_news_delete(p),
                    _ => Ok(()),
                },
                DeserializedPayload::Reaction(ref p) => validation::validate_reaction(p),
                DeserializedPayload::Report(ref p) => validation::validate_report(p),
                DeserializedPayload::CounterVote(ref p) => validation::validate_counter_vote(p),
                DeserializedPayload::ChannelMute(ref p) => validation::validate_channel_mute(p),
                DeserializedPayload::DeviceDelegation(ref p) => {
                    validation::validate_device_delegation(p)
                }
                DeserializedPayload::Follow(ref p) => {
                    validation::validate_follow(resolved_author, p)
                }
                DeserializedPayload::Unfollow(ref p) => {
                    validation::validate_unfollow(resolved_author, p)
                }
                DeserializedPayload::ChannelAddModerator(ref p) => {
                    validation::validate_channel_add_moderator(p)
                }
                DeserializedPayload::ChannelRemoveModerator(ref p) => {
                    validation::validate_channel_remove_moderator(p)
                }
                DeserializedPayload::ChannelKick(ref p) => {
                    validation::validate_channel_kick(p)
                }
                DeserializedPayload::ChannelBan(ref p) => {
                    validation::validate_channel_ban(p)
                }
                DeserializedPayload::ChannelUnban(ref p) => {
                    validation::validate_channel_unban(p)
                }
                DeserializedPayload::ChannelPinMessage(ref p) => {
                    validation::validate_channel_pin(p)
                }
                DeserializedPayload::ChannelUnpinMessage(ref p) => {
                    validation::validate_channel_unpin(p)
                }
                DeserializedPayload::ChannelInvite(ref p) => {
                    validation::validate_channel_invite(p)
                }
                DeserializedPayload::NewsRepost(ref p) => {
                    validation::validate_news_repost(resolved_author, p)
                }
                DeserializedPayload::ContentRequest(ref p) => {
                    validation::validate_content_request(p)
                }
                DeserializedPayload::DirectMessage(ref p) => {
                    validation::validate_direct_message(resolved_author, p)
                }
                DeserializedPayload::SettingsSync(ref p) => {
                    validation::validate_settings_sync(p)
                }
                DeserializedPayload::DeviceRevocation(ref p) => {
                    validation::validate_device_revocation(p)
                }
                DeserializedPayload::DeletionRequest(ref p) => {
                    validation::validate_deletion_request(p)
                }
                DeserializedPayload::PrivateChannelKeyDistribution(ref p) => {
                    validation::validate_private_channel_key_distribution(p)
                }
                DeserializedPayload::ChannelKeyEnvelope(ref p) => {
                    validation::validate_channel_key_envelope(p)
                }
                // Types with no specific validation rules (NewsReaction uses existing validate_reaction)
                _ => Ok(()),
            },
            Err(e) => Err(validation::ValidationError(format!(
                "payload deserialization failed: {}",
                e
            ))),
        }
    }

    /// Check if the author is banned from the target channel.
    /// Rejects channel-scoped messages from banned users.
    /// Also enforces ban expiration: expired bans are cleaned up on read.
    fn check_channel_ban(&self, envelope: &Envelope, resolved_author: &str) -> Result<(), String> {
        let channel_id = match self.extract_channel_id(envelope) {
            Some(id) => id,
            None => return Ok(()), // not a channel-scoped message
        };

        let ban_key = schema::encode_channel_ban_key(channel_id, resolved_author);
        match self.storage.get_cf(schema::cf::CHANNEL_BANS, &ban_key) {
            Ok(Some(data)) => {
                // Check if ban has expired
                if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&data) {
                    let duration = record.get("duration_secs")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    if duration > 0 {
                        let banned_at = record.get("banned_at")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let elapsed_secs = (now_ms.saturating_sub(banned_at)) / 1000;
                        if elapsed_secs >= duration {
                            // Ban expired — clean up and allow
                            let _ = self.storage.delete_cf(schema::cf::CHANNEL_BANS, &ban_key);
                            return Ok(());
                        }
                    }
                }
                Err(format!("user is banned from channel {}", channel_id))
            }
            _ => Ok(()),
        }
    }

    /// Check if user is muted in the channel. Muted users cannot send ChatMessage
    /// or ChatReaction to the channel. Other message types (edits, deletes, leaves) are allowed.
    fn check_channel_mute(&self, envelope: &Envelope, resolved_author: &str) -> Result<(), String> {
        // Only enforce mute on ChatMessage and ChatReaction
        match envelope.msg_type {
            MessageType::ChatMessage | MessageType::ChatReaction => {}
            _ => return Ok(()),
        }
        let channel_id = match self.extract_channel_id(envelope) {
            Some(id) => id,
            None => return Ok(()),
        };
        match self.storage.is_channel_muted(channel_id, resolved_author) {
            Ok(true) => Err(format!("user is muted in channel {}", channel_id)),
            _ => Ok(()),
        }
    }

    /// Enforce read-only / broadcast channel posting policy (protocol spec §3.6).
    ///
    /// When the channel's runtime `channel_type` is `ReadPublic` (1), only the
    /// channel creator and moderators can publish `ChatMessage`, `ChatEdit`,
    /// or `ChatDelete`. `ChatReaction` is intentionally allowed for all
    /// members so read-only channels remain socially interactive. All other
    /// message types fall through unaffected.
    ///
    /// The check reads the L2 channel record (not the on-chain immutable
    /// channel_type) so creators can flip broadcast mode at runtime via
    /// `ChannelUpdate`. If the channel record is missing, the check is a
    /// no-op — other pipeline steps already reject orphan messages.
    fn check_readonly_channel(&self, envelope: &Envelope, resolved_author: &str) -> Result<(), String> {
        // Only gates write actions on chat content. Reactions and admin/control
        // messages have their own authorization paths.
        match envelope.msg_type {
            MessageType::ChatMessage | MessageType::ChatEdit | MessageType::ChatDelete => {}
            _ => return Ok(()),
        }
        let channel_id = match self.extract_channel_id(envelope) {
            Some(id) => id,
            None => return Ok(()),
        };
        let key = channel_id.to_be_bytes();
        let data = match self.storage.get_cf(schema::cf::CHANNELS, &key) {
            Ok(Some(d)) => d,
            // Channel not found: let downstream handle it. A truly orphan write
            // will be rejected by validation/index pathways.
            Ok(None) => return Ok(()),
            Err(e) => return Err(format!("storage error: {}", e)),
        };
        let meta: serde_json::Value = match serde_json::from_slice(&data) {
            Ok(m) => m,
            Err(_) => return Ok(()), // corrupt metadata — fail open, log elsewhere
        };
        // Tolerate both numeric and legacy string encodings for channel_type
        // (an older migration normalized strings → u8, but defensive parsing
        // here keeps the gate working even on unmigrated rows).
        let channel_type = match meta.get("channel_type") {
            Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
            Some(serde_json::Value::String(s)) => match s.as_str() {
                "Public" => 0,
                "ReadPublic" => 1,
                "Private" => 2,
                _ => 0,
            },
            _ => 0,
        };
        if channel_type != 1 {
            // Not ReadPublic — no read-only policy to enforce.
            return Ok(());
        }
        // Allow creator and moderators (any permission level — creator/mod
        // status is the authorization, not a specific permission flag).
        // Use the already-loaded `meta` to read `creator` directly — avoids a
        // second CHANNELS read and removes a TOCTOU window if the channel
        // record were deleted between reads (use unwrap_or(false) on the mod
        // check for the same reason; missing data ⇒ deny, not error).
        let is_creator = meta
            .get("creator")
            .and_then(|v| v.as_str())
            .map(|c| c == resolved_author)
            .unwrap_or(false);
        if is_creator {
            return Ok(());
        }
        if self
            .storage
            .is_channel_moderator(channel_id, resolved_author)
            .unwrap_or(false)
        {
            return Ok(());
        }
        Err(format!(
            "channel {} is read-only; only creator and moderators may post",
            channel_id
        ))
    }

    /// Authorize channel admin operations per spec section 2.6.
    /// Verifies the sender has the required role/permissions.
    /// Uses `resolved_author` (wallet address) for all permission checks.
    fn authorize_channel_action(&self, envelope: &Envelope, resolved_author: &str) -> Result<(), String> {
        match envelope.msg_type {
            // Creator-only actions
            MessageType::ChannelAddModerator | MessageType::ChannelRemoveModerator => {
                let channel_id = self
                    .extract_channel_id(envelope)
                    .ok_or("missing or invalid channel_id")?;
                if !self.is_channel_creator(channel_id, resolved_author)? {
                    return Err("only the channel creator can manage moderators".into());
                }
                // Cannot remove self (creator)
                if envelope.msg_type == MessageType::ChannelRemoveModerator {
                    if let Ok(p) = rmp_serde::from_slice::<ChannelRemoveModeratorPayload>(&envelope.payload) {
                        if p.target_user == resolved_author {
                            return Err("cannot remove yourself as moderator".into());
                        }
                    }
                }
                Ok(())
            }
            // Creator + mods with can_kick
            MessageType::ChannelKick => {
                let channel_id = self
                    .extract_channel_id(envelope)
                    .ok_or("missing or invalid channel_id")?;
                if let Ok(p) = rmp_serde::from_slice::<ChannelKickPayload>(&envelope.payload) {
                    // Cannot kick the creator
                    if self.is_channel_creator(channel_id, &p.target_user)? {
                        return Err("cannot kick the channel creator".into());
                    }
                }
                self.require_mod_permission(channel_id, resolved_author, "can_kick")
            }
            // Creator + mods with can_ban
            MessageType::ChannelBan => {
                let channel_id = self
                    .extract_channel_id(envelope)
                    .ok_or("missing or invalid channel_id")?;
                if let Ok(p) = rmp_serde::from_slice::<ChannelBanPayload>(&envelope.payload) {
                    if self.is_channel_creator(channel_id, &p.target_user)? {
                        return Err("cannot ban the channel creator".into());
                    }
                }
                self.require_mod_permission(channel_id, resolved_author, "can_ban")
            }
            MessageType::ChannelUnban => {
                let channel_id = self
                    .extract_channel_id(envelope)
                    .ok_or("missing or invalid channel_id")?;
                self.require_mod_permission(channel_id, resolved_author, "can_ban")
            }
            // Creator + mods with can_pin
            MessageType::ChannelPinMessage | MessageType::ChannelUnpinMessage => {
                let channel_id = self
                    .extract_channel_id(envelope)
                    .ok_or("missing or invalid channel_id")?;
                self.require_mod_permission(channel_id, resolved_author, "can_pin")
            }
            // Creator + mods with can_mute
            MessageType::ChannelMute => {
                let channel_id = self
                    .extract_channel_id(envelope)
                    .ok_or("missing or invalid channel_id")?;
                if let Ok(p) = rmp_serde::from_slice::<ChannelMutePayload>(&envelope.payload) {
                    if self.is_channel_creator(channel_id, &p.target_user)? {
                        return Err("cannot mute the channel creator".into());
                    }
                }
                self.require_mod_permission(channel_id, resolved_author, "can_mute")
            }
            // Creator + mods with can_edit_info
            MessageType::ChannelUpdate => {
                let channel_id = self
                    .extract_channel_id(envelope)
                    .ok_or("missing or invalid channel_id")?;
                self.require_mod_permission(channel_id, resolved_author, "can_edit_info")
            }
            // Private channel join: allow with explicit invite or via invite link.
            // Knowing the channel_id (via shared invite link) is sufficient proof
            // of invitation unless the owner has explicitly disabled invite links.
            MessageType::ChannelJoin => {
                if let Ok(p) = rmp_serde::from_slice::<ChannelJoinPayload>(&envelope.payload) {
                    if let Ok(Some(data)) = self.storage.get_cf(
                        schema::cf::CHANNELS, &p.channel_id.to_be_bytes(),
                    ) {
                        if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&data) {
                            let is_private = match meta.get("channel_type") {
                                Some(serde_json::Value::Number(n)) => n.as_u64() == Some(2),
                                Some(serde_json::Value::String(s)) => s == "Private",
                                _ => false,
                            };
                            if is_private {
                                let invite_key = schema::encode_channel_invite_key(
                                    p.channel_id, resolved_author,
                                );
                                let has_invite = self.storage.exists_cf(
                                    schema::cf::CHANNEL_INVITES, &invite_key,
                                ).unwrap_or(false);
                                // Only reject if invite links are explicitly disabled
                                let links_disabled = meta
                                    .get("invite_links_disabled")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);
                                if !has_invite && links_disabled {
                                    return Err("private channel: invite required".into());
                                }
                            }
                        }
                    }
                }
                Ok(())
            }
            // Creator + any moderator
            MessageType::ChannelInvite => {
                let channel_id = self
                    .extract_channel_id(envelope)
                    .ok_or("missing or invalid channel_id")?;
                if self.is_channel_creator(channel_id, resolved_author)? {
                    return Ok(());
                }
                if self.storage.is_channel_moderator(channel_id, resolved_author)
                    .unwrap_or(false)
                {
                    return Ok(());
                }
                Err("only creator or moderators can invite users".into())
            }
            // Private channel key distribution — creator or moderator of the channel.
            // Only valid on the anchor node (where the channel was created).
            MessageType::PrivateChannelKeyDistribution => {
                let channel_id = self
                    .extract_channel_id(envelope)
                    .ok_or("missing or invalid channel_id")?;
                // Verify this is a private channel and we are the anchor node
                let key = channel_id.to_be_bytes();
                let meta_bytes = self.storage.get_cf(schema::cf::CHANNELS, &key)
                    .map_err(|e| format!("storage error: {}", e))?
                    .ok_or_else(|| "channel not found".to_string())?;
                let meta: serde_json::Value = serde_json::from_slice(&meta_bytes)
                    .map_err(|e| format!("invalid channel metadata: {}", e))?;
                let channel_type = meta.get("channel_type").and_then(|v| v.as_u64()).unwrap_or(0);
                if channel_type != 2 {
                    return Err("key distribution is only for private channels".into());
                }
                if self.is_channel_creator(channel_id, resolved_author)? {
                    return Ok(());
                }
                if self.storage.is_channel_moderator(channel_id, resolved_author)
                    .unwrap_or(false)
                {
                    return Ok(());
                }
                Err("only creator or moderators can distribute channel keys".into())
            }
            // Per-device key envelope (0x61). Scope-aware authorization:
            //  - DM: `conversation_id` is one-way, so the publisher proves
            //    participation by supplying `peer` such that
            //    `key_scope == compute_conversation_id(author, peer)`, and the
            //    envelope must target one of the two participants. This blocks an
            //    outsider from planting key envelopes into someone else's DM scope.
            //  - Channel: membership-gated — lands in P2.
            MessageType::ChannelKeyEnvelope => {
                let p = rmp_serde::from_slice::<ChannelKeyEnvelopePayload>(&envelope.payload)
                    .map_err(|e| format!("invalid channel key envelope: {}", e))?;
                match p.scope_kind {
                    crate::messages::types::key_scope_kind::DM => {
                        let peer = p
                            .peer
                            .as_deref()
                            .ok_or("DM key envelope missing peer")?;
                        let expected =
                            crate::crypto::compute_conversation_id(resolved_author, peer);
                        if p.key_scope != expected {
                            return Err(
                                "key_scope does not match the (author, peer) conversation".into(),
                            );
                        }
                        if p.target.as_str() != resolved_author && p.target.as_str() != peer {
                            return Err("target must be a conversation participant".into());
                        }
                        Ok(())
                    }
                    crate::messages::types::key_scope_kind::CHANNEL => {
                        // P2 OECK: a per-device wrapped channel epoch key. The scope
                        // must be the deterministic channel scope, and BOTH the
                        // publisher (author) and the recipient (target) must be
                        // members — non-members can neither distribute nor receive a
                        // channel key. (WHICH member may start a NEW epoch — creator/
                        // mods — is a client-enforced policy; the node bounds key flow
                        // to the membership set, which is the security boundary.)
                        let channel_id = p
                            .channel_id
                            .ok_or("channel key envelope missing channel_id")?;
                        let expected = crate::crypto::compute_channel_scope(channel_id);
                        if p.key_scope != expected {
                            return Err("key_scope does not match the channel".into());
                        }
                        if !self.is_channel_member(channel_id, resolved_author)? {
                            return Err("only a channel member may publish a channel key".into());
                        }
                        if !self.is_channel_member(channel_id, &p.target)? {
                            return Err("channel key target must be a channel member".into());
                        }
                        Ok(())
                    }
                    other => Err(format!("invalid scope_kind: {}", other)),
                }
            }
            _ => Ok(()),
        }
    }

    /// Authorize edit and delete operations.
    ///
    /// Verifies:
    /// 1. The target message exists.
    /// 2. The resolved author matches the original message's author.
    /// 3. For edits: the edit is within the 30-minute window.
    /// 4. For NewsEdit: the user must be a registered user (exists in USERS CF).
    fn authorize_edit_delete(
        &self,
        envelope: &Envelope,
        resolved_author: &str,
        now_ms: u64,
    ) -> Result<(), String> {
        // Only applies to edit/delete message types
        let (target_id, is_edit) = match envelope.msg_type {
            MessageType::ChatEdit | MessageType::DirectMessageEdit | MessageType::NewsEdit => {
                let payload = rmp_serde::from_slice::<EditPayload>(&envelope.payload)
                    .map_err(|e| format!("failed to deserialize edit payload: {}", e))?;
                (payload.target_id, true)
            }
            MessageType::ChatDelete | MessageType::DirectMessageDelete | MessageType::NewsDelete => {
                let payload = rmp_serde::from_slice::<DeletePayload>(&envelope.payload)
                    .map_err(|e| format!("failed to deserialize delete payload: {}", e))?;
                (payload.target_id, false)
            }
            _ => return Ok(()), // not an edit/delete message
        };

        // 1. Look up the original message
        let original_bytes = self
            .storage
            .get_cf(schema::cf::MESSAGES, &target_id)
            .map_err(|e| format!("storage error: {}", e))?
            .ok_or_else(|| "target message not found".to_string())?;

        // 2. Deserialize the original envelope to get its author
        let original_envelope: Envelope = rmp_serde::from_slice(&original_bytes)
            .map_err(|e| format!("failed to deserialize original message: {}", e))?;

        // 3. Resolve the original author to wallet address
        let original_resolved = self
            .identity
            .resolve(&original_envelope.author)
            .map_err(|e| format!("failed to resolve original author: {}", e))?;

        // 4. Verify authorship — only the original author can edit/delete their message
        if resolved_author != original_resolved {
            return Err("only the original author can edit/delete this message".into());
        }

        // 5. For edits: enforce 30-minute window from original timestamp
        if is_edit {
            const EDIT_WINDOW_MS: u64 = 30 * 60 * 1000;
            if now_ms.saturating_sub(original_envelope.timestamp) > EDIT_WINDOW_MS {
                return Err("edit window expired (30 minutes from original message)".into());
            }
        }

        // 6. For NewsEdit: defense-in-depth check (Step 4d already gates this,
        // but verify on-chain registration here too for edit-specific flow).
        if envelope.msg_type == MessageType::NewsEdit {
            let is_verified = self
                .storage
                .get_cf(schema::cf::USERS, resolved_author.as_bytes())
                .ok()
                .flatten()
                .and_then(|data| serde_json::from_slice::<serde_json::Value>(&data).ok())
                .and_then(|v| v.get("registered_at")?.as_u64())
                .map_or(false, |ts| ts > 0);
            if !is_verified {
                return Err("news edits require on-chain registration".into());
            }
        }

        Ok(())
    }

    /// Extract the channel_id from channel-scoped message payloads.
    fn extract_channel_id(&self, envelope: &Envelope) -> Option<u64> {
        match envelope.msg_type {
            MessageType::ChatMessage => {
                rmp_serde::from_slice::<ChatMessagePayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            // W10 (audit 2026-06-07): ChannelJoin MUST be channel-scoped here so
            // the ban check (step 7b) sees it — otherwise a banned user can
            // simply re-`ChannelJoin` to rejoin a channel they were banned from.
            MessageType::ChannelJoin => {
                rmp_serde::from_slice::<ChannelJoinPayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChatEdit => {
                rmp_serde::from_slice::<EditPayload>(&envelope.payload)
                    .ok().and_then(|p| p.channel_id)
            }
            MessageType::ChatDelete => {
                rmp_serde::from_slice::<DeletePayload>(&envelope.payload)
                    .ok().and_then(|p| p.channel_id)
            }
            MessageType::ChatReaction => {
                rmp_serde::from_slice::<ReactionPayload>(&envelope.payload)
                    .ok().and_then(|p| p.channel_id)
            }
            MessageType::ChannelAddModerator => {
                rmp_serde::from_slice::<ChannelAddModeratorPayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelRemoveModerator => {
                rmp_serde::from_slice::<ChannelRemoveModeratorPayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelKick => {
                rmp_serde::from_slice::<ChannelKickPayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelBan => {
                rmp_serde::from_slice::<ChannelBanPayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelUnban => {
                rmp_serde::from_slice::<ChannelUnbanPayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelPinMessage => {
                rmp_serde::from_slice::<ChannelPinMessagePayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelUnpinMessage => {
                rmp_serde::from_slice::<ChannelUnpinMessagePayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelInvite => {
                rmp_serde::from_slice::<ChannelInvitePayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelUpdate => {
                rmp_serde::from_slice::<ChannelUpdatePayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelMute => {
                rmp_serde::from_slice::<ChannelMutePayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::PrivateChannelKeyDistribution => {
                rmp_serde::from_slice::<PrivateChannelKeyDistributionPayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            _ => None,
        }
    }

    /// Check if address is the channel creator by looking up channel metadata.
    fn is_channel_creator(&self, channel_id: u64, address: &str) -> Result<bool, String> {
        match self.storage.get_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes()) {
            Ok(Some(data)) => {
                if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&data) {
                    Ok(meta.get("creator").and_then(|v| v.as_str()) == Some(address))
                } else {
                    Ok(false)
                }
            }
            Ok(None) => Err(format!("channel {} not found", channel_id)),
            Err(e) => Err(format!("storage error: {}", e)),
        }
    }

    /// Check if `address` is a member of `channel_id`. The creator is added as a
    /// member (role "creator") at ChannelCreate, so this covers them too.
    fn is_channel_member(&self, channel_id: u64, address: &str) -> Result<bool, String> {
        let key = schema::encode_channel_member_key(channel_id, address);
        self.storage
            .exists_cf(schema::cf::CHANNEL_MEMBERS, &key)
            .map_err(|e| format!("storage error: {}", e))
    }

    /// Check if the user is the creator or a moderator with the required permission.
    fn require_mod_permission(
        &self,
        channel_id: u64,
        author: &str,
        permission: &str,
    ) -> Result<(), String> {
        // Creator has all permissions
        if self.is_channel_creator(channel_id, author)? {
            return Ok(());
        }

        // Check moderator permissions
        let mod_key = schema::encode_channel_moderator_key(channel_id, author);
        match self.storage.get_cf(schema::cf::CHANNEL_MODERATORS, &mod_key) {
            Ok(Some(data)) => {
                if let Ok(perms) = serde_json::from_slice::<serde_json::Value>(&data) {
                    let has_perm = perms.get(permission)
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if has_perm {
                        Ok(())
                    } else {
                        Err(format!("moderator lacks '{}' permission", permission))
                    }
                } else {
                    Err("corrupt moderator permissions".into())
                }
            }
            Ok(None) => Err("not a moderator of this channel".into()),
            Err(e) => Err(format!("storage error: {}", e)),
        }
    }

    /// Add a member to a channel (idempotent — skips if already member).
    /// Updates the member_count in channel metadata.
    fn add_channel_member(&self, channel_id: u64, address: &str, timestamp: u64, role: &str) -> Result<bool> {
        // Check channel exists
        let channel_key = channel_id.to_be_bytes();
        let channel_data = self.storage.get_cf(schema::cf::CHANNELS, &channel_key)?;
        if channel_data.is_none() {
            return Ok(false); // channel doesn't exist
        }

        let member_key = schema::encode_channel_member_key(channel_id, address);
        if self.storage.get_cf(schema::cf::CHANNEL_MEMBERS, &member_key)?.is_some() {
            return Ok(false); // already a member
        }

        let record = serde_json::json!({
            "joined_at": timestamp,
            "role": role,
        });
        let record_bytes = serde_json::to_vec(&record)
            .context("serializing member record")?;
        self.storage.put_cf(schema::cf::CHANNEL_MEMBERS, &member_key, &record_bytes)?;

        // Update member_count in channel metadata
        if let Some(data) = channel_data {
            if let Ok(mut meta) = serde_json::from_slice::<serde_json::Value>(&data) {
                let count = meta.get("member_count").and_then(|v| v.as_u64()).unwrap_or(0);
                meta["member_count"] = serde_json::json!(count + 1);
                if let Ok(bytes) = serde_json::to_vec(&meta) {
                    let _ = self.storage.put_cf(schema::cf::CHANNELS, &channel_key, &bytes);
                }
            }
        }

        Ok(true)
    }

    /// Remove a member from a channel. Updates member_count.
    fn remove_channel_member(&self, channel_id: u64, address: &str) -> Result<()> {
        let member_key = schema::encode_channel_member_key(channel_id, address);
        self.storage.delete_cf(schema::cf::CHANNEL_MEMBERS, &member_key)?;

        // Decrement member_count in channel metadata
        let channel_key = channel_id.to_be_bytes();
        if let Some(data) = self.storage.get_cf(schema::cf::CHANNELS, &channel_key)? {
            if let Ok(mut meta) = serde_json::from_slice::<serde_json::Value>(&data) {
                let count = meta.get("member_count").and_then(|v| v.as_u64()).unwrap_or(1);
                meta["member_count"] = serde_json::json!(count.saturating_sub(1));
                if let Ok(bytes) = serde_json::to_vec(&meta) {
                    let _ = self.storage.put_cf(schema::cf::CHANNELS, &channel_key, &bytes);
                }
            }
        }

        Ok(())
    }

    /// Update storage indexes based on message type.
    fn update_indexes(&self, envelope: &Envelope, resolved_author: &str) -> Result<()> {
        // P-1 (identity-sync): index a user's signed identity envelopes
        // (delegation/revocation/profile/follow/unfollow) under their wallet so
        // the per-wallet identity-sync responder can re-serve them to a node the
        // user just connected to. `resolved_author` is the wallet for all five
        // types (DeviceDelegation is wallet-authored; the others are
        // device-authored and resolve to the wallet). The original signed
        // envelope is already kept in MESSAGES; this index just enumerates it.
        if matches!(
            envelope.msg_type,
            MessageType::ProfileUpdate
                | MessageType::DeviceDelegation
                | MessageType::DeviceRevocation
                | MessageType::Follow
                | MessageType::Unfollow
                | MessageType::DeviceEncBinding
                | MessageType::DeviceEncRevoke
        ) {
            let key = schema::encode_identity_envelope_key(
                resolved_author,
                envelope.msg_type_u8(),
                envelope.timestamp,
                &envelope.msg_id,
            );
            self.storage
                .put_cf(schema::cf::IDENTITY_ENVELOPES, &key, &[])?;
        }

        // P-3b (channel-metadata): index a channel's L2 metadata/membership
        // envelopes per channel so the channel-history reconcile can serve them
        // to a node that chain-discovered the channel (the scanner only writes
        // the skeleton — no display_name/logo/members).
        if matches!(
            envelope.msg_type,
            MessageType::ChannelCreate
                | MessageType::ChannelUpdate
                | MessageType::ChannelJoin
                | MessageType::ChannelLeave
        ) {
            if let Ok(p) = rmp_serde::from_slice::<serde_json::Value>(&envelope.payload) {
                if let Some(cid) = p.get("channel_id").and_then(|v| v.as_u64()) {
                    let key = schema::encode_channel_meta_key(
                        cid,
                        envelope.msg_type_u8(),
                        envelope.timestamp,
                        &envelope.msg_id,
                    );
                    self.storage
                        .put_cf(schema::cf::CHANNEL_META_MSGS, &key, &[])?;
                }
            }
        }

        match envelope.msg_type {
            MessageType::ChatMessage => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChatMessagePayload>(&envelope.payload)
                {
                    // Sort key is the message's wall-clock timestamp (ms), NOT
                    // `lamport_ts` — clients send `lamport_ts: 0`, which made the
                    // index sort by msg_id (random) and broke the unread fast-skip
                    // (0 <= any read cursor). `timestamp` is part of the signed
                    // envelope, so this key is identical on every node → globally
                    // consistent chronological ordering + a valid reconcile cursor
                    // + a working `key_ts <= last_read` skip in get_unread_counts.
                    let key = schema::encode_channel_msg_key(
                        payload.channel_id,
                        envelope.timestamp,
                        &envelope.msg_id,
                    );
                    self.storage
                        .put_cf(schema::cf::CHANNEL_MSGS, &key, &[])?;
                    self.storage
                        .increment_stat(schema::state_keys::TOTAL_CHANNEL_MESSAGES)?;

                    // Auto-add author as channel member on first message
                    let _ = self.add_channel_member(
                        payload.channel_id,
                        resolved_author,
                        envelope.timestamp,
                        "member",
                    );
                }
            }
            MessageType::DirectMessage => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<DirectMessagePayload>(&envelope.payload)
                {
                    // 1. Index the message by conversation
                    let msg_key = schema::encode_dm_msg_key(
                        &payload.conversation_id,
                        envelope.timestamp,
                        &envelope.msg_id,
                    );
                    self.storage
                        .put_cf(schema::cf::DM_MESSAGES, &msg_key, &[])?;

                    // 2. Update conversation index for BOTH participants
                    // Sender's entry: value = recipient address (the peer)
                    let sender_conv_key = schema::encode_dm_conversation_key(
                        resolved_author.as_bytes(),
                        envelope.timestamp,
                        &payload.conversation_id,
                    );
                    self.storage.put_cf(
                        schema::cf::DM_CONVERSATIONS,
                        &sender_conv_key,
                        payload.recipient.as_bytes(),
                    )?;

                    // Recipient's entry: value = sender address (the peer)
                    let recipient_conv_key = schema::encode_dm_conversation_key(
                        payload.recipient.as_bytes(),
                        envelope.timestamp,
                        &payload.conversation_id,
                    );
                    self.storage.put_cf(
                        schema::cf::DM_CONVERSATIONS,
                        &recipient_conv_key,
                        resolved_author.as_bytes(),
                    )?;
                }
            }
            MessageType::NewsPost => {
                let key =
                    schema::encode_news_key(envelope.timestamp, &envelope.msg_id);
                self.storage
                    .put_cf(schema::cf::NEWS_FEED, &key, &[])?;
                self.storage
                    .increment_stat(schema::state_keys::TOTAL_NEWS_MESSAGES)?;

                // Index by author (resolved wallet address)
                let author_key = schema::encode_news_by_author_key(
                    resolved_author,
                    envelope.timestamp,
                    &envelope.msg_id,
                );
                self.storage
                    .put_cf(schema::cf::NEWS_BY_AUTHOR, &author_key, &[])?;

                // Index by tags
                if let Ok(payload) =
                    rmp_serde::from_slice::<NewsPostPayload>(&envelope.payload)
                {
                    for tag in &payload.tags {
                        let tag_key = schema::encode_news_by_tag_key(
                            tag,
                            envelope.timestamp,
                            &envelope.msg_id,
                        );
                        self.storage
                            .put_cf(schema::cf::NEWS_BY_TAG, &tag_key, &[])?;
                    }
                }
            }
            MessageType::Follow => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<FollowPayload>(&envelope.payload)
                {
                    // P-2: LWW by signed timestamp — a stale/replayed follow is
                    // a no-op so a malicious backfill can't tamper the graph.
                    self.storage.apply_follow_edge(
                        resolved_author,
                        &payload.target,
                        true,
                        envelope.timestamp,
                    )?;
                }
            }
            MessageType::Unfollow => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<UnfollowPayload>(&envelope.payload)
                {
                    self.storage.apply_follow_edge(
                        resolved_author,
                        &payload.target,
                        false,
                        envelope.timestamp,
                    )?;
                }
            }
            MessageType::ChannelCreate => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelCreatePayload>(&envelope.payload)
                {
                    let key = payload.channel_id.to_be_bytes();
                    if let Ok(Some(existing)) = self.storage.get_cf(schema::cf::CHANNELS, &key) {
                        // Channel already exists — typically the chain scanner's
                        // skeleton (slug/creator, no L2 fields) for a public
                        // channel, or a prior apply. MERGE only the L2 fields
                        // (display_name/description) and ONLY if the envelope
                        // author is the channel's creator. Never clobber the
                        // on-chain creator/member_count and never re-count
                        // TOTAL_CHANNELS. This makes a gossiped/backfilled
                        // ChannelCreate safe and lets a public channel's name
                        // follow it to every node that chain-discovered it.
                        if let Ok(mut meta) =
                            serde_json::from_slice::<serde_json::Value>(&existing)
                        {
                            let is_creator = meta
                                .get("creator")
                                .and_then(|v| v.as_str())
                                == Some(resolved_author);
                            if is_creator {
                                if let Some(obj) = meta.as_object_mut() {
                                    if payload.display_name.is_some() {
                                        obj.insert(
                                            "display_name".into(),
                                            serde_json::json!(payload.display_name),
                                        );
                                    }
                                    if payload.description.is_some() {
                                        obj.insert(
                                            "description".into(),
                                            serde_json::json!(payload.description),
                                        );
                                    }
                                    let bytes = serde_json::to_vec(&meta)
                                        .context("serializing merged channel metadata")?;
                                    self.storage.put_cf(schema::cf::CHANNELS, &key, &bytes)?;
                                }
                            } else {
                                debug!(
                                    channel_id = payload.channel_id,
                                    author = %resolved_author,
                                    "ChannelCreate for existing channel from non-creator — ignoring L2 merge"
                                );
                            }
                        }
                    } else {
                        // New channel (L2-only/private, or a public channel not
                        // yet chain-scanned). Create the full record; the chain
                        // scanner merges its on-chain fields later if/when it
                        // sees the event (it preserves these L2 fields).
                        let meta = serde_json::json!({
                            "channel_id": payload.channel_id,
                            "slug": payload.slug,
                            "channel_type": payload.channel_type as u8,
                            "creator": resolved_author,
                            "created_at": envelope.timestamp,
                            "display_name": payload.display_name,
                            "description": payload.description,
                            "member_count": 0,
                        });
                        let meta_bytes = serde_json::to_vec(&meta)
                            .context("serializing channel metadata")?;
                        self.storage.put_cf(schema::cf::CHANNELS, &key, &meta_bytes)?;
                        self.storage
                            .increment_stat(schema::state_keys::TOTAL_CHANNELS)?;

                        // Add creator as first member (increments member_count to 1)
                        let _ = self.add_channel_member(
                            payload.channel_id,
                            resolved_author,
                            envelope.timestamp,
                            "creator",
                        );
                    }
                }
            }
            MessageType::ChannelJoin => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelJoinPayload>(&envelope.payload)
                {
                    // Validates channel exists and is idempotent (skips if already member)
                    let _ = self.add_channel_member(
                        payload.channel_id,
                        resolved_author,
                        envelope.timestamp,
                        "member",
                    );
                }
            }
            MessageType::ChannelLeave => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelLeavePayload>(&envelope.payload)
                {
                    self.remove_channel_member(payload.channel_id, resolved_author)?;
                }
            }
            MessageType::NewsComment => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<NewsCommentPayload>(&envelope.payload)
                {
                    // Index under parent post for threaded retrieval
                    let comment_key = schema::encode_news_comment_key(
                        &payload.post_id,
                        envelope.timestamp,
                        &envelope.msg_id,
                    );
                    self.storage
                        .put_cf(schema::cf::NEWS_COMMENTS, &comment_key, &[])?;

                    // Also index in NEWS_FEED so comments appear in the timeline
                    let feed_key =
                        schema::encode_news_key(envelope.timestamp, &envelope.msg_id);
                    self.storage
                        .put_cf(schema::cf::NEWS_FEED, &feed_key, &[])?;
                }
            }
            MessageType::NewsReaction => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ReactionPayload>(&envelope.payload)
                {
                    self.storage.toggle_news_reaction(
                        &payload.target_id,
                        &payload.emoji,
                        resolved_author,
                        payload.remove,
                    )?;
                }
            }
            MessageType::NewsRepost => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<NewsRepostPayload>(&envelope.payload)
                {
                    self.storage.add_repost(
                        &payload.original_id,
                        resolved_author,
                        &envelope.msg_id,
                    )?;
                    // Also index the repost in the global news feed
                    let key =
                        schema::encode_news_key(envelope.timestamp, &envelope.msg_id);
                    self.storage
                        .put_cf(schema::cf::NEWS_FEED, &key, &[])?;
                    self.storage
                        .increment_stat(schema::state_keys::TOTAL_NEWS_MESSAGES)?;
                }
            }
            MessageType::ChannelAddModerator => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelAddModeratorPayload>(&envelope.payload)
                {
                    let key = schema::encode_channel_moderator_key(
                        payload.channel_id,
                        &payload.target_user,
                    );
                    let perms = serde_json::to_vec(&payload.permissions)
                        .context("serializing moderator permissions")?;
                    self.storage
                        .put_cf(schema::cf::CHANNEL_MODERATORS, &key, &perms)?;
                }
            }
            MessageType::ChannelRemoveModerator => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelRemoveModeratorPayload>(&envelope.payload)
                {
                    let key = schema::encode_channel_moderator_key(
                        payload.channel_id,
                        &payload.target_user,
                    );
                    self.storage
                        .delete_cf(schema::cf::CHANNEL_MODERATORS, &key)?;
                }
            }
            MessageType::ChannelKick => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelKickPayload>(&envelope.payload)
                {
                    self.remove_channel_member(payload.channel_id, &payload.target_user)?;
                }
            }
            MessageType::ChannelBan => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelBanPayload>(&envelope.payload)
                {
                    // Remove from members (updates member_count)
                    self.remove_channel_member(payload.channel_id, &payload.target_user)?;

                    // Add to bans
                    let ban_key = schema::encode_channel_ban_key(
                        payload.channel_id,
                        &payload.target_user,
                    );
                    let record = serde_json::json!({
                        "reason": payload.reason,
                        "duration_secs": payload.duration_secs,
                        "banned_at": envelope.timestamp,
                        "banned_by": resolved_author,
                    });
                    let record_bytes = serde_json::to_vec(&record)
                        .context("serializing ban record")?;
                    self.storage.put_cf(
                        schema::cf::CHANNEL_BANS,
                        &ban_key,
                        &record_bytes,
                    )?;
                }
            }
            MessageType::ChannelUnban => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelUnbanPayload>(&envelope.payload)
                {
                    let key = schema::encode_channel_ban_key(
                        payload.channel_id,
                        &payload.target_user,
                    );
                    self.storage
                        .delete_cf(schema::cf::CHANNEL_BANS, &key)?;
                }
            }
            MessageType::ChannelPinMessage => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelPinMessagePayload>(&envelope.payload)
                {
                    let pin_count = self.storage.get_pin_count(payload.channel_id)?;
                    // If max 10 pins, FIFO — remove oldest if at limit
                    if pin_count >= 10 {
                        let prefix = payload.channel_id.to_be_bytes();
                        if let Ok(entries) = self.storage.prefix_iter_cf(
                            schema::cf::CHANNEL_PINS,
                            &prefix,
                            1,
                        ) {
                            if let Some((oldest_key, _)) = entries.first() {
                                self.storage
                                    .delete_cf(schema::cf::CHANNEL_PINS, oldest_key)?;
                            }
                        }
                    }
                    // Use monotonically increasing sequence to avoid pin_order collisions
                    let seq_key = format!("pin_seq:{}", payload.channel_id);
                    let next_seq = match self.storage.get_cf(schema::cf::NODE_STATE, seq_key.as_bytes())? {
                        Some(bytes) if bytes.len() == 4 => {
                            u32::from_be_bytes(bytes.try_into().unwrap_or([0; 4])) + 1
                        }
                        _ => 0,
                    };
                    self.storage.put_cf(schema::cf::NODE_STATE, seq_key.as_bytes(), &next_seq.to_be_bytes())?;
                    let key = schema::encode_channel_pin_key(
                        payload.channel_id,
                        next_seq,
                        &payload.msg_id,
                    );
                    self.storage
                        .put_cf(schema::cf::CHANNEL_PINS, &key, &[])?;
                }
            }
            MessageType::ChannelUnpinMessage => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelUnpinMessagePayload>(&envelope.payload)
                {
                    // Scan for the pinned msg_id and remove it
                    let prefix = payload.channel_id.to_be_bytes();
                    if let Ok(entries) = self.storage.prefix_iter_cf(
                        schema::cf::CHANNEL_PINS,
                        &prefix,
                        10,
                    ) {
                        for (key, _) in entries {
                            if key.len() >= 44 {
                                let stored_id: [u8; 32] =
                                    key[12..44].try_into().unwrap_or([0u8; 32]);
                                if stored_id == payload.msg_id {
                                    self.storage
                                        .delete_cf(schema::cf::CHANNEL_PINS, &key)?;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            MessageType::ChannelInvite => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelInvitePayload>(&envelope.payload)
                {
                    let key = schema::encode_channel_invite_key(
                        payload.channel_id,
                        &payload.target_user,
                    );
                    let record = serde_json::json!({
                        "invited_by": resolved_author,
                        "timestamp": envelope.timestamp,
                    });
                    let record_bytes = serde_json::to_vec(&record)
                        .context("serializing invite record")?;
                    self.storage.put_cf(
                        schema::cf::CHANNEL_INVITES,
                        &key,
                        &record_bytes,
                    )?;
                }
            }
            MessageType::ChannelUpdate => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelUpdatePayload>(&envelope.payload)
                {
                    tracing::debug!(
                        channel_id = payload.channel_id,
                        author = %resolved_author,
                        has_name = payload.display_name.is_some(),
                        has_desc = payload.description.is_some(),
                        has_type_change = payload.channel_type.is_some(),
                        has_threads_toggle = payload.threads_enabled.is_some(),
                        "Processing ChannelUpdate"
                    );
                    // Merge updated fields into existing channel metadata
                    let key = payload.channel_id.to_be_bytes();
                    if let Ok(Some(existing)) = self.storage.get_cf(schema::cf::CHANNELS, &key) {
                        if let Ok(mut meta) = serde_json::from_slice::<serde_json::Value>(&existing) {
                            if let Some(name) = &payload.display_name {
                                meta["display_name"] = serde_json::Value::String(name.clone());
                            }
                            if let Some(desc) = &payload.description {
                                meta["description"] = serde_json::Value::String(desc.clone());
                            }
                            if let Some(logo) = &payload.logo_cid {
                                meta["logo_cid"] = serde_json::Value::String(logo.clone());
                            }
                            if let Some(banner) = &payload.banner_cid {
                                meta["banner_cid"] = serde_json::Value::String(banner.clone());
                            }
                            if let Some(url) = &payload.website_url {
                                meta["website_url"] = serde_json::Value::String(url.clone());
                            }
                            if let Some(tags) = &payload.tags {
                                meta["tags"] = serde_json::json!(tags);
                            }
                            // Runtime channel_type flip: only Public ⇄ ReadPublic.
                            // The "to Private" case is already refused at
                            // validation (see validate_channel_update). Here we
                            // additionally guard the "from Private" case, which
                            // validation cannot see because it doesn't know the
                            // current channel state. Spec §3.6.
                            if let Some(new_type) = payload.channel_type {
                                let current_type = match meta.get("channel_type") {
                                    Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
                                    Some(serde_json::Value::String(s)) => match s.as_str() {
                                        "Public" => 0,
                                        "ReadPublic" => 1,
                                        "Private" => 2,
                                        _ => 0,
                                    },
                                    _ => 0,
                                };
                                let new_type_u8 = new_type as u8;
                                if current_type == 2 {
                                    tracing::warn!(
                                        channel_id = payload.channel_id,
                                        new_type = new_type_u8,
                                        "ChannelUpdate channel_type flip refused: channel is Private"
                                    );
                                    // Drop only the channel_type field; sibling
                                    // fields (description, etc.) still apply.
                                    // The payload was authorized (mod with
                                    // can_edit_info) and the rest is benign.
                                } else {
                                    meta["channel_type"] = serde_json::json!(new_type_u8);
                                }
                            }
                            // Threaded mode toggle: pure boolean flag, no
                            // structural migration (existing messages remain
                            // readable in either mode). Spec §3.6.
                            if let Some(threaded) = payload.threads_enabled {
                                meta["threads_enabled"] = serde_json::Value::Bool(threaded);
                            }
                            let meta_bytes = serde_json::to_vec(&meta)
                                .context("serializing updated channel metadata")?;
                            self.storage.put_cf(schema::cf::CHANNELS, &key, &meta_bytes)?;
                        }
                    }
                }
            }
            MessageType::ChatEdit => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<EditPayload>(&envelope.payload)
                {
                    self.storage.store_edit(
                        &payload.target_id,
                        envelope.timestamp,
                        &envelope.msg_id,
                    )?;
                }
            }
            MessageType::ChatDelete => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<DeletePayload>(&envelope.payload)
                {
                    self.storage.store_deletion_marker(
                        &payload.target_id,
                        resolved_author,
                        envelope.timestamp,
                    )?;
                }
            }
            MessageType::ChatReaction => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ReactionPayload>(&envelope.payload)
                {
                    self.storage.toggle_chat_reaction(
                        &payload.target_id,
                        &payload.emoji,
                        resolved_author,
                        payload.remove,
                    )?;
                }
            }
            MessageType::DirectMessageEdit => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<EditPayload>(&envelope.payload)
                {
                    self.storage.store_edit(
                        &payload.target_id,
                        envelope.timestamp,
                        &envelope.msg_id,
                    )?;
                }
            }
            MessageType::DirectMessageDelete => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<DeletePayload>(&envelope.payload)
                {
                    self.storage.store_deletion_marker(
                        &payload.target_id,
                        resolved_author,
                        envelope.timestamp,
                    )?;
                }
            }
            // DM reactions are encrypted — the reaction payload is end-to-end encrypted
            // content, so we cannot parse emoji/target_id for indexing. The envelope is
            // already stored in MESSAGES (step 8). No additional indexing needed.
            MessageType::DirectMessageReaction => {}
            MessageType::NewsEdit => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<EditPayload>(&envelope.payload)
                {
                    self.storage.store_edit(
                        &payload.target_id,
                        envelope.timestamp,
                        &envelope.msg_id,
                    )?;
                }
            }
            MessageType::NewsDelete => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<DeletePayload>(&envelope.payload)
                {
                    self.storage.store_deletion_marker(
                        &payload.target_id,
                        resolved_author,
                        envelope.timestamp,
                    )?;
                }
            }
            MessageType::SettingsSync => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<SettingsSyncPayload>(&envelope.payload)
                {
                    // Store the full payload as JSON so the client can retrieve
                    // encrypted_settings, nonce, and key_epoch for decryption.
                    let json = serde_json::json!({
                        "encrypted_settings": payload.encrypted_settings,
                        "nonce": payload.nonce,
                        "key_epoch": payload.key_epoch,
                    });
                    self.storage.store_settings(
                        resolved_author,
                        json.to_string().as_bytes(),
                    )?;
                    debug!(author = %resolved_author, "Settings synced");
                }
            }
            MessageType::DeviceEncBinding => {
                // P0 E2E (protocol §2.4): record a per-device X25519 encryption public
                // key so senders can wrap message keys to each of this wallet's devices.
                // The wallet signature over the canonical claim was verified at
                // `verify_signature`. Apply last-write-wins so a replayed/stale binding
                // can neither overwrite newer state (CRITICAL-2) nor resurrect a key a
                // strictly-newer revoke tombstoned (CRITICAL-1); cap directory growth.
                if let Ok(payload) =
                    rmp_serde::from_slice::<DeviceEncBindingPayload>(&envelope.payload)
                {
                    let enc_pub = payload.enc_pub.to_ascii_lowercase();
                    let device_id = payload.device_id.to_ascii_lowercase();
                    let key = schema::encode_device_enc_key(resolved_author, &enc_pub);
                    if self.enc_key_is_newer(&key, envelope.timestamp)? {
                        // §2.4 one-active-enc_pub-per-device: plan which prior keys
                        // for THIS device this binding supersedes (and whether it
                        // itself lost the LWW race against a newer key for the device).
                        let (newer_exists, to_revoke) = self.plan_enc_key_supersede(
                            resolved_author,
                            &device_id,
                            &enc_pub,
                            envelope.timestamp,
                        )?;
                        if newer_exists {
                            // A strictly-newer (or equal-ts) key for this device is
                            // already active: store this binding as a tombstone so a
                            // later replay cannot resurrect it as a second active key.
                            let record = serde_json::json!({
                                "enc_pub": enc_pub,
                                "device_id": device_id,
                                "ts": envelope.timestamp,
                                "revoked": true,
                                "revoked_at": envelope.timestamp,
                                "superseded": true,
                            });
                            self.storage.put_cf(
                                schema::cf::DEVICE_ENC_KEYS,
                                &key,
                                record.to_string().as_bytes(),
                            )?;
                            debug!(wallet = %resolved_author, %enc_pub, %device_id,
                                "stale per-device enc binding superseded on arrival");
                        } else {
                            // Cap check counts current active keys; superseding this
                            // device's older key frees a slot, so subtract those so a
                            // legitimate rotation never trips the per-wallet cap.
                            let active = self
                                .count_active_enc_keys(resolved_author, &enc_pub)?
                                .saturating_sub(to_revoke.len());
                            if active >= MAX_ENC_KEYS_PER_WALLET {
                                warn!(wallet = %resolved_author, active,
                                    "enc-key cap reached; binding ignored");
                            } else {
                                // Tombstone the older enc_pub(s) for this device first,
                                // then activate the new one — both writes happen only
                                // once the cap check has passed.
                                for (rk, old_enc) in &to_revoke {
                                    let tomb = serde_json::json!({
                                        "enc_pub": old_enc,
                                        "device_id": device_id,
                                        "ts": envelope.timestamp,
                                        "revoked": true,
                                        "revoked_at": envelope.timestamp,
                                        "superseded_by": enc_pub,
                                    });
                                    self.storage.put_cf(
                                        schema::cf::DEVICE_ENC_KEYS,
                                        rk,
                                        tomb.to_string().as_bytes(),
                                    )?;
                                }
                                let record = serde_json::json!({
                                    "enc_pub": enc_pub,
                                    "device_id": device_id,
                                    "created_at": envelope.timestamp,
                                    "ts": envelope.timestamp,
                                    "revoked": false,
                                });
                                self.storage.put_cf(
                                    schema::cf::DEVICE_ENC_KEYS,
                                    &key,
                                    record.to_string().as_bytes(),
                                )?;
                                if to_revoke.is_empty() {
                                    debug!(wallet = %resolved_author, %enc_pub,
                                        "Device enc key bound");
                                } else {
                                    debug!(wallet = %resolved_author, %enc_pub, %device_id,
                                        superseded = to_revoke.len(),
                                        "Device enc key bound; superseded prior key(s)");
                                }
                            }
                        }
                    }
                }
            }
            MessageType::DeviceEncRevoke => {
                // Write a revocation TOMBSTONE (not a bare delete) so a replayed older
                // binding cannot resurrect a retired key (CRITICAL-1). LWW-guarded.
                if let Ok(payload) =
                    rmp_serde::from_slice::<DeviceEncRevokePayload>(&envelope.payload)
                {
                    let enc_pub = payload.enc_pub.to_ascii_lowercase();
                    let key = schema::encode_device_enc_key(resolved_author, &enc_pub);
                    if self.enc_key_is_newer(&key, envelope.timestamp)? {
                        let record = serde_json::json!({
                            "enc_pub": enc_pub,
                            "ts": envelope.timestamp,
                            "revoked": true,
                            "revoked_at": envelope.timestamp,
                        });
                        self.storage.put_cf(
                            schema::cf::DEVICE_ENC_KEYS,
                            &key,
                            record.to_string().as_bytes(),
                        )?;
                        debug!(wallet = %resolved_author, %enc_pub, "Device enc key revoked");
                    }
                }
            }
            MessageType::DeviceDelegation => {
                // B2 propagation arm (l2-node 0.46.8+, spec 1 §device-
                // delegation, spec 3 §router).
                //
                // A wallet-signed DeviceDelegation envelope reaches this
                // arm via two paths:
                //   1. The owning wallet POSTed a wallet-signed envelope
                //      through `/api/v1/messages` (or the augmented
                //      `register_device` path) on this node — local
                //      apply.
                //   2. Another node received the same envelope on
                //      `topic_network` and relayed it via gossip — remote
                //      apply, the cross-node propagation case B2 was
                //      tracking before this version.
                //
                // Both paths converge here. We compute the device address
                // from the payload's pubkey, look up any existing claim
                // for this (wallet, device) tuple, and apply only when
                // the incoming envelope is newer than what we already
                // have. Idempotency is keyed on (envelope.author = wallet,
                // payload.device_pub_key, envelope.timestamp): equal-or-
                // older timestamps are no-ops so cross-node gossip
                // replays don't churn the index. Different wallets
                // claiming the same device key cannot happen for an
                // honest client (the same Ed25519 key cannot be signed
                // for by two distinct wallets without sharing the
                // private key); the existing forward-map last-write-wins
                // would otherwise leak the device under whichever wallet
                // got there last.
                if let Ok(payload) =
                    rmp_serde::from_slice::<DeviceDelegationPayload>(&envelope.payload)
                {
                    let pubkey_bytes = hex::decode(&payload.device_pub_key)
                        .context("invalid device_pub_key hex")?;
                    let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
                        .map_err(|_| anyhow::anyhow!("device_pub_key must be 32 bytes"))?;
                    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_array)
                        .map_err(|e| anyhow::anyhow!("invalid Ed25519 public key: {}", e))?;
                    let device_address = crypto::device_pubkey_to_address(&verifying_key)
                        .map_err(|e| anyhow::anyhow!("failed to encode device address: {}", e))?;

                    // P-2: reject a delegation older-or-equal to a revocation
                    // tombstone. A stale/replayed DeviceDelegation must never
                    // resurrect a revoked (possibly compromised) device — a
                    // genuine re-delegation carries a newer timestamp. Closes
                    // the resurrection/auth-bypass vector on every path (gossip
                    // and identity-sync backfill).
                    if let Some(revoked_at) = self
                        .identity
                        .get_device_revoked_at(&device_address)
                        .context("checking device revocation tombstone")?
                    {
                        if envelope.timestamp <= revoked_at {
                            debug!(
                                device = %device_address,
                                revoked_at,
                                incoming_ts = envelope.timestamp,
                                "DeviceDelegation older-or-equal to revocation tombstone — rejected"
                            );
                            return Ok(());
                        }
                    }

                    // Code Audit W1 (0.46.8): bail on storage faults
                    // rather than falling through to the apply path.
                    // A storage error in `list_devices` previously
                    // resolved to "no existing claim found", which
                    // would overwrite a newer claim with an older
                    // gossip replay — inverting the LWW guard. With
                    // `?` propagation, the storage fault aborts the
                    // arm cleanly and the envelope is retried on the
                    // next gossip arrival.
                    let existing_claim = self
                        .identity
                        .list_devices(resolved_author)
                        .context("list_devices for DeviceDelegation idempotency check")?
                        .into_iter()
                        .find(|c| c.device_address == device_address);

                    // Idempotency check: same (wallet, device) tuple
                    // with greater-or-equal timestamp = no-op. First
                    // writer wins on equal ms; documented behaviour.
                    if let Some(ref existing) = existing_claim {
                        if existing.registered_at >= envelope.timestamp {
                            debug!(
                                device = %device_address,
                                wallet = %resolved_author,
                                existing_ts = existing.registered_at,
                                incoming_ts = envelope.timestamp,
                                "DeviceDelegation older or equal — no-op"
                            );
                            return Ok(());
                        }
                    }

                    // Security Audit W1 (0.46.8): enforce
                    // MAX_DEVICES_PER_WALLET on the receive side too.
                    // The local `register_device` HTTP path already
                    // enforces this (routes.rs), but a wallet pushing
                    // DeviceDelegation envelopes directly to gossip
                    // bypassed that check pre-0.46.8 because there
                    // was no apply arm; now there is, the cap belongs
                    // here as well. Excludes the current (wallet,
                    // device) tuple from the count so an in-place
                    // refresh always succeeds.
                    const MAX_DEVICES_PER_WALLET: usize = 10;
                    let existing_count = self
                        .identity
                        .list_devices(resolved_author)
                        .context("list_devices for DeviceDelegation cap check")?
                        .into_iter()
                        .filter(|c| c.device_address != device_address)
                        .count();
                    if existing_count >= MAX_DEVICES_PER_WALLET {
                        warn!(
                            wallet = %resolved_author,
                            existing_count,
                            cap = MAX_DEVICES_PER_WALLET,
                            "DeviceDelegation arrival exceeded per-wallet device cap; dropping"
                        );
                        return Ok(());
                    }

                    let claim = crate::storage::rocks::DeviceClaim {
                        device_address: device_address.clone(),
                        wallet_address: resolved_author.to_string(),
                        device_pubkey_hex: payload.device_pub_key.to_ascii_lowercase(),
                        // The envelope itself carries the wallet
                        // signature; we don't have it as a separate
                        // hex string here. The local-API
                        // register_device path stores the original
                        // claim signature; gossip-received delegations
                        // rely on the envelope signature as the
                        // proof, so an empty marker is correct here.
                        wallet_signature: String::new(),
                        registered_at: envelope.timestamp,
                    };
                    // `identity.register_device` enforces the
                    // cross-wallet-hijack defense from Security Audit
                    // C1 (0.46.8) — if a different wallet currently
                    // owns this device address, the call errors out
                    // and we log + drop. The wallet whose gossip
                    // envelope arrived second cannot steal a device
                    // already mapped to wallet A without an
                    // intervening DeviceRevocation.
                    match self.identity.register_device(&claim) {
                        Ok(()) => {
                            debug!(
                                device = %device_address,
                                wallet = %resolved_author,
                                ts = envelope.timestamp,
                                "Device delegation applied"
                            );
                        }
                        Err(e) => {
                            warn!(
                                device = %device_address,
                                attempted_wallet = %resolved_author,
                                error = %e,
                                "DeviceDelegation refused by identity layer (cross-wallet hijack defense or storage fault)"
                            );
                        }
                    }
                }
            }
            MessageType::DeviceRevocation => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<DeviceRevocationPayload>(&envelope.payload)
                {
                    // Convert hex pubkey to ogd1 device address
                    let pubkey_bytes = hex::decode(&payload.device_pub_key)
                        .context("invalid device_pub_key hex")?;
                    let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
                        .map_err(|_| anyhow::anyhow!("device_pub_key must be 32 bytes"))?;
                    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_array)
                        .map_err(|e| anyhow::anyhow!("invalid Ed25519 public key: {}", e))?;
                    let device_address = crypto::device_pubkey_to_address(&verifying_key)
                        .map_err(|e| anyhow::anyhow!("failed to encode device address: {}", e))?;

                    let revoked = self
                        .identity
                        .revoke_device(&device_address, resolved_author, envelope.timestamp)
                        .context("revoking device")?;
                    if revoked {
                        debug!(
                            device = %device_address,
                            wallet = %resolved_author,
                            "Device revoked"
                        );
                    } else {
                        warn!(
                            device = %device_address,
                            wallet = %resolved_author,
                            "Device revocation failed: device not found or not owned"
                        );
                    }
                }
            }
            MessageType::DeletionRequest => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<DeletionRequestPayload>(&envelope.payload)
                {
                    match payload.delete_type {
                        DeletionType::SingleMessage => {
                            if let Some(target_id) = payload.target_id {
                                self.storage.store_deletion_marker(
                                    &target_id,
                                    resolved_author,
                                    envelope.timestamp,
                                )?;
                                debug!(
                                    target = %hex::encode(target_id),
                                    author = %resolved_author,
                                    "Single message deletion marker stored"
                                );
                            }
                        }
                        DeletionType::AllUserContent => {
                            // Mark all of the user's news posts as deleted.
                            let prefix = {
                                let mut p = Vec::with_capacity(resolved_author.len() + 1);
                                p.extend_from_slice(resolved_author.as_bytes());
                                p.push(0xFF);
                                p
                            };
                            // audit 2026-06-07 (W12): page through ALL of the
                            // user's news posts instead of a single 10k-capped
                            // scan that silently leaves data behind. Deletion
                            // markers live in a separate CF, so the NEWS_BY_AUTHOR
                            // rows are not consumed — we advance the cursor with
                            // `prefix_iter_cf_after` until the prefix is drained.
                            const PAGE: usize = 10_000;
                            let mut deleted_count: u64 = 0;
                            let mut cursor: Option<Vec<u8>> = None;
                            loop {
                                let entries = match &cursor {
                                    None => self.storage.prefix_iter_cf(
                                        schema::cf::NEWS_BY_AUTHOR,
                                        &prefix,
                                        PAGE,
                                    )?,
                                    Some(start) => self.storage.prefix_iter_cf_after(
                                        schema::cf::NEWS_BY_AUTHOR,
                                        start,
                                        &prefix,
                                        PAGE,
                                    )?,
                                };
                                if entries.is_empty() {
                                    break;
                                }
                                // Remember the last key to resume after this page.
                                cursor = entries.last().map(|(k, _)| k.clone());
                                let page_len = entries.len();
                                for (key, _) in &entries {
                                    // Key: (author, 0xFF, !timestamp:8, msg_id:32)
                                    if key.len() >= 32 {
                                        let msg_id: [u8; 32] = key[key.len() - 32..]
                                            .try_into()
                                            .unwrap_or([0u8; 32]);
                                        if msg_id != [0u8; 32] {
                                            self.storage.store_deletion_marker(
                                                &msg_id,
                                                resolved_author,
                                                envelope.timestamp,
                                            )?;
                                            deleted_count += 1;
                                        }
                                    }
                                }
                                // Short page = prefix exhausted.
                                if page_len < PAGE {
                                    break;
                                }
                            }
                            warn!(
                                author = %resolved_author,
                                news_posts_marked = deleted_count,
                                "AllUserContent deletion: marked news posts. \
                                 Channel message deletion is not yet implemented."
                            );
                        }
                    }
                }
            }
            MessageType::PrivateChannelKeyDistribution => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<PrivateChannelKeyDistributionPayload>(&envelope.payload)
                {
                    // Enforce epoch monotonicity — new epoch must be strictly greater
                    // than the current latest to prevent key history tampering
                    if let Ok(Some((current_epoch, _))) =
                        self.storage.get_private_channel_keys_latest(payload.channel_id)
                    {
                        if payload.epoch <= current_epoch {
                            return Err(anyhow::anyhow!(
                                "key distribution epoch {} must be > current epoch {}",
                                payload.epoch,
                                current_epoch
                            ));
                        }
                    }

                    // Serialize the key distribution data (member_keys map)
                    let key_data = serde_json::to_vec(&serde_json::json!({
                        "epoch": payload.epoch,
                        "member_keys": payload.member_keys,
                        "distributed_by": resolved_author,
                        "timestamp": envelope.timestamp,
                    })).context("serializing key distribution")?;

                    self.storage.store_private_channel_keys(
                        payload.channel_id,
                        payload.epoch,
                        &key_data,
                    )?;

                    debug!(
                        channel_id = payload.channel_id,
                        epoch = payload.epoch,
                        members = payload.member_keys.len(),
                        author = %resolved_author,
                        "Private channel key distribution stored"
                    );
                }
            }
            MessageType::ChannelKeyEnvelope => {
                if let Ok(p) =
                    rmp_serde::from_slice::<ChannelKeyEnvelopePayload>(&envelope.payload)
                {
                    // Store the opaque per-device wrapped key (first-write-wins). The
                    // node never decrypts it; the recipient device unwraps with its own
                    // X25519 enc privkey on retrieval.
                    let record = serde_json::to_vec(&serde_json::json!({
                        "eph_pub": hex::encode(p.eph_pub),
                        "nonce": hex::encode(p.nonce),
                        "wrapped": hex::encode(&p.wrapped),
                        "epoch": p.epoch,
                        "scope_kind": p.scope_kind,
                        "author": resolved_author,
                        "timestamp": envelope.timestamp,
                    }))
                    .context("serializing channel key envelope")?;
                    // DM keys are PER-SENDER (keyed by the publishing author so each
                    // participant's conv_key coexists). A channel epoch key is a SINGLE
                    // GROUP key shared by all members, so it's stored author-agnostically
                    // (canonical empty author) — any member fetches their wrapped copy by
                    // (channel_scope, target=self, device, epoch) without knowing which
                    // member published it. First-write-wins per device still yields one
                    // key per (target, device, epoch); the actual publisher is preserved
                    // in the record's `author` field for traceability.
                    let store_author = if p.scope_kind
                        == crate::messages::types::key_scope_kind::CHANNEL
                    {
                        ""
                    } else {
                        resolved_author
                    };
                    match self.storage.put_channel_key_envelope_fww(
                        &p.key_scope,
                        &p.target,
                        store_author,
                        &p.device_id,
                        p.epoch,
                        &record,
                        MAX_CHANNEL_KEY_ENVELOPES_PER_SCOPE,
                    )? {
                        crate::storage::rocks::KeyEnvelopeStore::Stored => {
                            debug!(epoch = p.epoch, target = %p.target, "Channel key envelope stored");
                        }
                        crate::storage::rocks::KeyEnvelopeStore::AlreadyPresent => {
                            debug!(epoch = p.epoch, target = %p.target, "Channel key envelope already present (first-write-wins)");
                        }
                        crate::storage::rocks::KeyEnvelopeStore::ScopeFull => {
                            warn!(target = %p.target, key_scope = %hex::encode(p.key_scope), "Channel key envelope rejected: scope full");
                        }
                    }
                }
            }
            MessageType::ProfileUpdate => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ProfileUpdatePayload>(&envelope.payload)
                {
                    let is_new = !self
                        .storage
                        .exists_cf(schema::cf::USERS, resolved_author.as_bytes())?;

                    // Load existing user record or create a new one.
                    // New records from ProfileUpdate get registered_at: 0 to distinguish
                    // them from on-chain registered users (where the chain scanner sets
                    // a real timestamp). This enables tiered access: unverified users
                    // can chat/post but need on-chain registration for advanced features.
                    let existing = self
                        .storage
                        .get_cf(schema::cf::USERS, resolved_author.as_bytes())?;
                    let mut record = match &existing {
                        Some(bytes) => serde_json::from_slice::<serde_json::Value>(bytes)
                            .unwrap_or_else(|_| serde_json::json!({})),
                        None => serde_json::json!({
                            "address": resolved_author,
                            "public_key": "",
                            "registered_at": 0,
                        }),
                    };

                    // P-2: last-writer-wins by signed timestamp. Ignore a
                    // stale/replayed ProfileUpdate so a malicious backfill can't
                    // downgrade a profile to an older version. (on-chain
                    // `registered_at` verification is separate and unaffected.)
                    let prev_profile_ts = record
                        .get("profile_updated_at")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    if envelope.timestamp <= prev_profile_ts {
                        debug!(
                            author = %resolved_author,
                            prev = prev_profile_ts,
                            incoming = envelope.timestamp,
                            "ProfileUpdate older-or-equal — no-op (LWW)"
                        );
                        return Ok(());
                    }

                    // Capture old display_name BEFORE merge so we can clean up the
                    // USERS_BY_NAME prefix index if the name actually changed.
                    let old_name = record
                        .get("display_name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    // Merge profile fields
                    if let serde_json::Value::Object(ref mut map) = record {
                        if let Some(name) = &payload.display_name {
                            map.insert("display_name".into(), serde_json::json!(name));
                        }
                        if let Some(avatar) = &payload.avatar_cid {
                            map.insert("avatar_cid".into(), serde_json::json!(avatar));
                        }
                        if let Some(bio) = &payload.bio {
                            map.insert("bio".into(), serde_json::json!(bio));
                        }
                        // Record the LWW watermark for the next apply.
                        map.insert(
                            "profile_updated_at".into(),
                            serde_json::json!(envelope.timestamp),
                        );
                    }

                    let bytes = serde_json::to_vec(&record)
                        .context("serializing user record")?;
                    self.storage.put_cf(
                        schema::cf::USERS,
                        resolved_author.as_bytes(),
                        &bytes,
                    )?;

                    // Maintain USERS_BY_NAME prefix index for @-mention autocomplete.
                    // If the name changed, remove the old index row first; then write
                    // the new one. Empty / whitespace-only names produce no index row
                    // (a user with no name simply isn't autocomplete-discoverable).
                    let new_name = record
                        .get("display_name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    if old_name != new_name {
                        if let Some(old) = &old_name {
                            if !old.trim().is_empty() {
                                let old_key = schema::encode_users_by_name_key(
                                    &old.to_lowercase(),
                                    resolved_author,
                                );
                                let _ = self.storage.delete_cf(schema::cf::USERS_BY_NAME, &old_key);
                            }
                        }
                    }
                    if let Some(new) = &new_name {
                        if !new.trim().is_empty() {
                            let new_key = schema::encode_users_by_name_key(
                                &new.to_lowercase(),
                                resolved_author,
                            );
                            let _ = self.storage.put_cf(
                                schema::cf::USERS_BY_NAME,
                                &new_key,
                                &[],
                            );
                        }
                    }

                    if is_new {
                        self.storage
                            .increment_stat(schema::state_keys::TOTAL_USERS)?;
                    }

                    tracing::info!(address = %resolved_author, "Profile updated");
                }
            }
            MessageType::Report => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ReportPayload>(&envelope.payload)
                {
                    let reason = format!("{:?}", payload.reason);
                    let details = payload.details.as_deref().unwrap_or("");
                    self.storage.store_report(
                        &payload.target_id,
                        resolved_author,
                        &reason,
                        details,
                        envelope.timestamp,
                    )?;
                }
            }
            MessageType::CounterVote => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<CounterVotePayload>(&envelope.payload)
                {
                    self.storage.store_counter_vote(
                        &payload.target_id,
                        resolved_author,
                        envelope.timestamp,
                    )?;
                }
            }
            MessageType::ChannelMute => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelMutePayload>(&envelope.payload)
                {
                    let reason = payload.reason.as_deref().unwrap_or("");
                    self.storage.store_channel_mute(
                        payload.channel_id,
                        &payload.target_user,
                        resolved_author,
                        payload.duration_secs,
                        reason,
                        envelope.timestamp,
                    )?;
                }
            }
            MessageType::NodeAnnouncement => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<NodeAnnouncementPayload>(&envelope.payload)
                {
                    // Verify node_id matches the envelope author's public key.
                    // node_id = Base58(SHA-256(public_key)[:20])
                    let expected_node_id = {
                        use sha2::{Digest, Sha256};
                        let pubkey_bytes = crate::crypto::address_to_pubkey_bytes(&envelope.author)
                            .context("invalid author address in NodeAnnouncement")?;
                        let hash = Sha256::digest(&pubkey_bytes);
                        bs58::encode(&hash[..20]).into_string()
                    };
                    if payload.node_id != expected_node_id {
                        warn!(
                            claimed = %payload.node_id,
                            expected = %expected_node_id,
                            author = %envelope.author,
                            "NodeAnnouncement node_id mismatch — rejecting"
                        );
                        return Ok(());
                    }

                    // Validate payload bounds
                    if payload.channels.len() > 10_000 {
                        warn!(node_id = %payload.node_id, count = payload.channels.len(),
                            "NodeAnnouncement channels list too large — rejecting");
                        return Ok(());
                    }
                    if let Some(ref ep) = payload.api_endpoint {
                        if ep.len() > 256
                            || (!ep.starts_with("http://") && !ep.starts_with("https://"))
                        {
                            warn!(node_id = %payload.node_id,
                                "NodeAnnouncement invalid api_endpoint — rejecting");
                            return Ok(());
                        }
                    }

                    // Cap peer directory size (evict oldest if at limit)
                    let peer_count = self.storage
                        .prefix_iter_cf(schema::cf::PEER_DIRECTORY, &[], 10_001)?
                        .len();
                    if peer_count >= 10_000 {
                        // Already at capacity — only allow updates to existing entries
                        if self.storage.get_cf(
                            schema::cf::PEER_DIRECTORY,
                            payload.node_id.as_bytes(),
                        )?.is_none() {
                            debug!(node_id = %payload.node_id,
                                "Peer directory at capacity, ignoring new node");
                            return Ok(());
                        }
                    }

                    // Filter out private channels from the announcement.
                    // Per spec §3.14: the channels field MUST only contain public (0x00) and
                    // read-public (0x01) channel IDs. Private channels are never announced.
                    // This is defense-in-depth — well-behaved nodes won't include them, but
                    // we strip them here in case a misbehaving node does.
                    let public_channels: Vec<u64> = payload.channels.iter()
                        .filter(|&&ch_id| {
                            let key = ch_id.to_be_bytes();
                            match self.storage.get_cf(schema::cf::CHANNELS, &key) {
                                Ok(Some(meta_bytes)) => {
                                    match serde_json::from_slice::<serde_json::Value>(&meta_bytes) {
                                        Ok(meta) => {
                                            let ct = meta.get("channel_type")
                                                .and_then(|v| v.as_u64())
                                                .unwrap_or(0);
                                            ct != 2 // exclude private channels
                                        }
                                        Err(_) => true, // unknown channel — keep it
                                    }
                                }
                                _ => true, // unknown channel — keep it (we may not have metadata)
                            }
                        })
                        .copied()
                        .collect();

                    let record = serde_json::json!({
                        "node_id": payload.node_id,
                        "api_endpoint": payload.api_endpoint,
                        "channels": public_channels,
                        "user_count": payload.user_count,
                        "last_seen": envelope.timestamp,
                        "ttl_seconds": payload.ttl_seconds,
                    });
                    let record_bytes = serde_json::to_vec(&record)
                        .context("serializing node announcement")?;
                    self.storage.put_cf(
                        schema::cf::PEER_DIRECTORY,
                        payload.node_id.as_bytes(),
                        &record_bytes,
                    )?;
                    debug!(node_id = %payload.node_id, "Peer directory updated from announcement");
                }
            }
            _ => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod enc_supersede_tests {
    use super::*;
    use tempfile::TempDir;

    fn router() -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        (MessageRouter::new(storage, identity, None), dir)
    }

    fn put_enc(r: &MessageRouter, wallet: &str, enc_pub: &str, device_id: &str, ts: u64, revoked: bool) {
        let key = schema::encode_device_enc_key(wallet, enc_pub);
        let rec = serde_json::json!({
            "enc_pub": enc_pub,
            "device_id": device_id,
            "created_at": ts,
            "ts": ts,
            "revoked": revoked,
        });
        r.storage
            .put_cf(schema::cf::DEVICE_ENC_KEYS, &key, rec.to_string().as_bytes())
            .unwrap();
    }

    #[test]
    fn supersedes_older_key_for_same_device() {
        let (r, _d) = router();
        let w = "klv1wallet";
        put_enc(&r, w, "aa", "dev1", 100, false);
        // A newer binding (ts=200) for the same device with a different enc_pub
        // supersedes the older one and does not lose the LWW race.
        let (newer, to_revoke) = r.plan_enc_key_supersede(w, "dev1", "bb", 200).unwrap();
        assert!(!newer, "incoming is newer, should not be marked superseded");
        assert_eq!(to_revoke.len(), 1);
        assert_eq!(to_revoke[0].1, "aa");
    }

    #[test]
    fn stale_binding_loses_to_newer_device_key() {
        let (r, _d) = router();
        let w = "klv1wallet";
        put_enc(&r, w, "bb", "dev1", 200, false);
        // An out-of-order replay (ts=100) for the same device must NOT revoke the
        // newer active key; it loses the race and is flagged for tombstoning.
        let (newer, to_revoke) = r.plan_enc_key_supersede(w, "dev1", "aa", 100).unwrap();
        assert!(newer, "incoming is older, should be superseded on arrival");
        assert!(to_revoke.is_empty());
    }

    #[test]
    fn leaves_other_devices_untouched() {
        let (r, _d) = router();
        let w = "klv1wallet";
        put_enc(&r, w, "aa", "dev1", 100, false);
        put_enc(&r, w, "cc", "dev2", 100, false);
        // Binding a new key for dev1 must not touch dev2's key.
        let (newer, to_revoke) = r.plan_enc_key_supersede(w, "dev1", "bb", 200).unwrap();
        assert!(!newer);
        assert_eq!(to_revoke.len(), 1);
        assert_eq!(to_revoke[0].1, "aa");
    }

    #[test]
    fn ignores_revoked_and_rebind_of_same_key() {
        let (r, _d) = router();
        let w = "klv1wallet";
        put_enc(&r, w, "aa", "dev1", 100, true); // already revoked
        // Re-binding the SAME enc_pub (keep == record) is a no-op for supersede.
        let (newer, to_revoke) = r.plan_enc_key_supersede(w, "dev1", "aa", 200).unwrap();
        assert!(!newer);
        assert!(to_revoke.is_empty());
    }

    #[test]
    fn empty_device_id_never_supersedes() {
        let (r, _d) = router();
        let w = "klv1wallet";
        put_enc(&r, w, "aa", "dev1", 100, false);
        let (newer, to_revoke) = r.plan_enc_key_supersede(w, "", "bb", 200).unwrap();
        assert!(!newer);
        assert!(to_revoke.is_empty());
    }

    // --- P2 channel-scope ChannelKeyEnvelope authorization ---

    fn make_channel(r: &MessageRouter, channel_id: u64, creator: &str) {
        let meta = serde_json::json!({ "channel_id": channel_id, "channel_type": 2u8, "creator": creator });
        r.storage
            .put_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes(), meta.to_string().as_bytes())
            .unwrap();
        add_member(r, channel_id, creator);
    }

    fn add_member(r: &MessageRouter, channel_id: u64, addr: &str) {
        let key = schema::encode_channel_member_key(channel_id, addr);
        r.storage.put_cf(schema::cf::CHANNEL_MEMBERS, &key, b"{}").unwrap();
    }

    fn channel_key_env(channel_id: u64, scope: [u8; 32], author: &str, target: &str) -> Envelope {
        let payload = crate::messages::types::ChannelKeyEnvelopePayload {
            key_scope: scope,
            scope_kind: crate::messages::types::key_scope_kind::CHANNEL,
            epoch: 1,
            target: target.to_string(),
            device_id: "ab".repeat(32),
            peer: None,
            channel_id: Some(channel_id),
            eph_pub: [0u8; 32],
            nonce: [0u8; 24],
            wrapped: vec![0u8; 48],
        };
        Envelope {
            version: 1,
            msg_type: MessageType::ChannelKeyEnvelope,
            msg_id: [0u8; 32],
            author: author.to_string(),
            timestamp: 1,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![0u8; 64],
            relay_path: vec![],
        }
    }

    #[test]
    fn channel_key_authz_member_to_member_ok() {
        let (r, _d) = router();
        let (cid, creator, member) = (7u64, "klv1creator", "klv1member");
        make_channel(&r, cid, creator);
        add_member(&r, cid, member);
        let scope = crate::crypto::compute_channel_scope(cid);
        let env = channel_key_env(cid, scope, creator, member);
        assert!(r.authorize_channel_action(&env, creator).is_ok());
    }

    #[test]
    fn channel_key_authz_rejects_non_member_author() {
        let (r, _d) = router();
        let (cid, creator, member, outsider) = (7u64, "klv1creator", "klv1member", "klv1outsider");
        make_channel(&r, cid, creator);
        add_member(&r, cid, member);
        let scope = crate::crypto::compute_channel_scope(cid);
        let env = channel_key_env(cid, scope, outsider, member);
        assert!(r.authorize_channel_action(&env, outsider).is_err());
    }

    #[test]
    fn channel_key_authz_rejects_non_member_target() {
        let (r, _d) = router();
        let (cid, creator, outsider) = (7u64, "klv1creator", "klv1outsider");
        make_channel(&r, cid, creator);
        let scope = crate::crypto::compute_channel_scope(cid);
        let env = channel_key_env(cid, scope, creator, outsider);
        assert!(r.authorize_channel_action(&env, creator).is_err());
    }

    #[test]
    fn channel_key_authz_rejects_scope_mismatch() {
        let (r, _d) = router();
        let (cid, creator) = (7u64, "klv1creator");
        make_channel(&r, cid, creator);
        // key_scope for a DIFFERENT channel → reject even though author is a member.
        let wrong_scope = crate::crypto::compute_channel_scope(999);
        let env = channel_key_env(cid, wrong_scope, creator, creator);
        assert!(r.authorize_channel_action(&env, creator).is_err());
    }
}
