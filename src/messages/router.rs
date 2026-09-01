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

/// Per-user, per-category rate limit counters (dual burst + sustained
/// windows — rate-limit rework, l2-node 0.122.0). A request is limited if
/// EITHER window is exceeded. For categories that don't distinguish burst
/// from sustained, both windows carry the same (max, window_ms) pair
/// (`RateLimits::flat`), making the pair redundant but behaviorally
/// identical to the old single-window check.
struct RateLimitEntry {
    burst_count: u32,
    burst_window_start: u64,
    sustained_count: u32,
    sustained_window_start: u64,
}

/// Resolved (max_count, window_ms) pair for both windows of a rate-limit
/// check. See `RateCategory::limits`.
#[derive(Debug, Clone, Copy)]
struct RateLimits {
    burst_max: u32,
    burst_window_ms: u64,
    sustained_max: u32,
    sustained_window_ms: u64,
}

impl RateLimits {
    /// A category with no burst/sustained distinction — both windows use
    /// the same (max, window_ms), so the dual check degenerates to the
    /// original single-window behavior.
    const fn flat(max: u32, window_ms: u64) -> Self {
        Self {
            burst_max: max,
            burst_window_ms: window_ms,
            sustained_max: max,
            sustained_window_ms: window_ms,
        }
    }
}

/// Burst window for `NewsPost` (10 minutes, both tiers).
const NEWS_BURST_WINDOW_MS: u64 = 10 * 60_000;
/// Sustained window for `NewsPost` (1 day, both tiers).
const NEWS_SUSTAINED_WINDOW_MS: u64 = 86_400_000;

/// TTL for the cached on-chain-registration lookup used by the rate
/// limiter (`is_registered_cached`). Registration is a rare, monotonic
/// transition (a wallet never un-registers), so a short TTL is enough to
/// take the storage read off the hot path without meaningfully delaying a
/// wallet's tier upgrade after it registers.
const REGISTRATION_CACHE_TTL_MS: u64 = 60_000;

/// Result of checking whether `address` is the creator of `channel_id`, distinguishing
/// "not the creator" from "the channel doesn't exist locally yet" (audit final
/// pre-mainnet W14). See `channel_creator_check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelCreatorCheck {
    IsCreator,
    NotCreator,
    Unknown,
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
    KeyVault,          // 10 per minute (E2E vault — debounced LWW republish)
    DeviceEnc,         // 10 per hour (audit final pre-mainnet W15)
    ChannelMembership, // 20 per hour (join/leave — audit final pre-mainnet Code Audit CRITICAL #1)
    Other,             // fallback: 100 per minute
}

impl RateCategory {
    /// Resolved rate limits for this category, tiered by on-chain
    /// registration where the rate-limit rework plan calls for it (news
    /// posts, chat messages, reposts — spec §2 Change A). `NewsPost` also
    /// gets the dual burst/sustained treatment (Change B) using the
    /// operator-configured, ceiling-clamped values from `ogmara.toml`
    /// (Change C); every other category stays a compiled flat constant.
    fn limits(self, registered: bool, rate_limits_config: &crate::config::RateLimitsConfig) -> RateLimits {
        match self {
            Self::ChatMessages => {
                RateLimits::flat(if registered { 60 } else { 30 }, 60_000)
            }
            Self::NewsPost => {
                if registered {
                    RateLimits {
                        burst_max: rate_limits_config.news_burst_registered,
                        burst_window_ms: NEWS_BURST_WINDOW_MS,
                        sustained_max: rate_limits_config.news_daily_registered,
                        sustained_window_ms: NEWS_SUSTAINED_WINDOW_MS,
                    }
                } else {
                    RateLimits {
                        burst_max: rate_limits_config.news_burst_unverified,
                        burst_window_ms: NEWS_BURST_WINDOW_MS,
                        sustained_max: rate_limits_config.news_daily_unverified,
                        sustained_window_ms: NEWS_SUSTAINED_WINDOW_MS,
                    }
                }
            }
            Self::Reaction => RateLimits::flat(60, 60_000),
            Self::Repost => {
                RateLimits::flat(if registered { 30 } else { 10 }, 3_600_000)
            }
            Self::ChannelAdmin => RateLimits::flat(30, 3_600_000),
            Self::ModeratorChange => RateLimits::flat(10, 86_400_000),
            Self::ChannelInvite => RateLimits::flat(20, 3_600_000),
            Self::PinUnpin => RateLimits::flat(20, 3_600_000),
            // Legit clients publish a 4 s-debounced last-write-wins vault; 10/min is
            // generous for that while bounding the 2 MB-per-write storage churn.
            Self::KeyVault => RateLimits::flat(10, 60_000),
            // Audit final pre-mainnet W15: device (re)binding is a rare, manual user
            // action (setting up a new device, occasional key rotation) — not a
            // high-frequency pattern, unlike this previously fell into `Other`'s
            // 100/min, which let a single wallet mint ~144,000 permanent
            // DEVICE_ENC_KEYS tombstone rows/day (each accepted DeviceEncBinding/
            // DeviceEncRevoke writes one, whether the enc_pub ends up active or
            // immediately superseded/revoked). 10/hour is generous for a user
            // configuring several devices in one sitting while cutting the abuse
            // ceiling ~600x (144,000/day → 240/day).
            Self::DeviceEnc => RateLimits::flat(10, 3_600_000),
            // Audit final pre-mainnet Code Audit CRITICAL #1: ChannelLeave has no
            // `requires_verified_identity()` gate and previously fell into `Other`'s
            // 100/min, letting a single wallet mint up to 144,000/day
            // `PENDING_CHANNEL_MEMBER_REMOVALS` rows (one per Leave against an
            // as-yet-unknown channel_id) — ~3x the reaper's drain ceiling of
            // 48,000/day (`CHANNEL_MEMBER_REMOVAL_REAP_BATCH_LIMIT` 2,000 rows/hour,
            // node.rs). Real join/leave activity is bursty-but-rare per wallet; 20/hour
            // is generous headroom while capping worst-case growth at 480/day/wallet,
            // well under the reaper's throughput.
            Self::ChannelMembership => RateLimits::flat(20, 3_600_000),
            Self::Other => RateLimits::flat(100, 60_000),
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
            | MessageType::ChannelUnban | MessageType::ChannelMute
            | MessageType::ChannelUnmute
            | MessageType::ChannelDelete => Self::ChannelAdmin,
            MessageType::ChannelAddModerator | MessageType::ChannelRemoveModerator
            | MessageType::PrivateChannelKeyDistribution => Self::ModeratorChange,
            MessageType::ChannelInvite => Self::ChannelInvite,
            MessageType::ChannelPinMessage | MessageType::ChannelUnpinMessage => Self::PinUnpin,
            MessageType::KeyVaultSync => Self::KeyVault,
            MessageType::DeviceEncBinding | MessageType::DeviceEncRevoke => Self::DeviceEnc,
            MessageType::ChannelJoin | MessageType::ChannelLeave => Self::ChannelMembership,
            _ => Self::Other,
        }
    }
}

/// P4: resolve a new channel's `(encryption_enabled, history_visibility)` from the
/// `ChannelCreate` payload, applying type-based defaults when the (legacy) client
/// omitted them. Private channels are always encrypted + ForwardOnly; Public/
/// ReadPublic default to NOT-encrypted when the field is absent (legacy plaintext
/// channels) but updated clients send `Some(true)` (encryption forced on for new
/// public channels) — and they default to FullHistory.
fn channel_encryption_defaults(payload: &ChannelCreatePayload) -> (bool, u8) {
    let is_private = matches!(payload.channel_type, ChannelType::Private);
    // Private channels are ALWAYS encrypted — never trust a client `Some(false)`
    // to create a plaintext private channel (that would silently break the
    // confidentiality guarantee + accept plaintext via `check_channel_encryption_required`).
    let enc = is_private || payload.encryption_enabled.unwrap_or(false);
    // 0 = ForwardOnly, 1 = FullHistory. Clamp an out-of-range client value to the
    // type default rather than storing an undefined visibility.
    let hist = match payload.history_visibility {
        Some(v) if v <= 1 => v,
        _ => {
            if is_private {
                0
            } else {
                1
            }
        }
    };
    (enc, hist)
}

/// Whether a pending `ChannelDelete` claim (audit final pre-mainnet W14) should be
/// honored against a channel that was just created with the given `creator`. Shared by
/// both places a channel's creator becomes known for the first time
/// (`update_indexes`'s `ChannelCreate` handler and the chain scanner's `ChannelCreated`
/// handler) so the match logic has one definition and a direct unit test independent of
/// either call site's storage I/O.
pub(crate) fn channel_delete_claim_matches(claim: Option<&(String, u64)>, creator: &str) -> bool {
    matches!(claim, Some((claimant, _)) if claimant == creator)
}

/// Max active encryption keys retained per wallet (protocol §2.4). Bounds the
/// `device_enc_keys` directory and the multi-device wrap fan-out.
const MAX_ENC_KEYS_PER_WALLET: usize = 10;

/// Max per-device key envelopes retained per `key_scope` (all targets/devices/
/// epochs). Bounds the `channel_keys` CF against a flood of envelopes addressed to
/// fabricated device ids (spec 8.1.1). Generous: covers many devices × retained
/// history epochs for a DM or channel.
const MAX_CHANNEL_KEY_ENVELOPES_PER_SCOPE: usize = 4096;

/// Max epochs a `ChannelKeyEnvelope` may sit AHEAD of a scope's current highest
/// epoch (P2d hardening). Rotation only ever needs `current_max + 1`; this headroom
/// covers concurrent rotators and cross-node lag. Without a ceiling, a member could
/// publish a key at a near-`u64::MAX` epoch, saturating the rotation floor (and
/// blowing past JS's safe-integer range) so the channel becomes permanently
/// unsendable. Generous enough that legitimate lag never trips it (an epoch jump
/// this large would require hundreds of un-propagated removals).
const CHANNEL_KEY_EPOCH_MAX_JUMP: u64 = 256;

/// The message router processes incoming messages through the full pipeline.
pub struct MessageRouter {
    storage: Storage,
    /// Device-to-wallet identity resolver.
    identity: IdentityResolver,
    /// Per-user, per-category rate limit counters: "(address:category)" → entry.
    rate_limits: DashMap<String, RateLimitEntry>,
    /// Operator-configured, ceiling-clamped `NewsPost` budgets
    /// (`api.rate_limits` in `ogmara.toml`, rate-limit rework l2-node
    /// 0.122.0). Other categories stay compiled constants — see
    /// `RateCategory::limits`.
    rate_limits_config: crate::config::RateLimitsConfig,
    /// Short-TTL cache of the on-chain-registration tiering lookup
    /// (`is_registered_cached`): "address" → (is_registered, cached_at_ms).
    /// Takes the USERS-CF read off the hot path for every rate-limited
    /// message — registration is rare and monotonic, so a 60s staleness
    /// window is harmless (see `REGISTRATION_CACHE_TTL_MS`).
    registration_cache: DashMap<String, (bool, u64)>,
    /// PoW anti-spam manager (None = PoW disabled).
    pow: Option<Arc<crate::pow::PowManager>>,
    /// This node's Klever network ("testnet"/"mainnet", from `config.network_id()`).
    /// Folded into every signed envelope's msg_id + signing domain (audit
    /// 2026-08-16 C1) so an envelope captured on one network can never verify
    /// on the other, even though both share the same wallet keys.
    network: String,
    /// Max `DM_MESSAGES` rows attributable to a single recipient wallet
    /// (`DmConfig::max_stored_messages_per_recipient`, audit final
    /// pre-mainnet W11). `0` = unlimited. See `reserve_dm_recipient_slot`.
    dm_recipient_cap: usize,
    /// Guards the read-then-write in `reserve_dm_recipient_slot` (Security
    /// Audit follow-up, W11): `process_message` is called concurrently from
    /// many Axum handlers against this same shared `MessageRouter`, so the
    /// cap check and the counter increment must happen as one atomic step
    /// under this lock — otherwise concurrent `DirectMessage`s to the same
    /// recipient can all pass a separate check before any of them
    /// increments, overshooting the configured cap. Global (not
    /// per-recipient): the critical section is two cheap RocksDB point
    /// operations (no content write inside the lock — `store_message`
    /// happens in Step 8, after the reservation), so contention cost is
    /// negligible relative to the rest of the pipeline.
    dm_recipient_cap_lock: std::sync::Mutex<()>,
    /// Shared with `NetworkService`/`MetricsCollector`/`AppState` (audit
    /// final pre-mainnet W35) — used here only to increment
    /// `failed_signature_verifications` on a Step 4b rejection, feeding the
    /// `FailedSignatureSpike` alert.
    counters: Arc<crate::metrics::counters::NetworkCounters>,
    /// Trending-hashtag aggregation policy (spec 3 §3.9). Consulted in
    /// `update_indexes` when a `NewsPost` is stored: gates whether the
    /// per-`(tag, hour)` HyperLogLog sketch in `HOT_TOPICS_LOCAL` is
    /// updated, and caps distinct tracked tags per bucket. Defaults to
    /// `HotTopicsConfig::default()`; production overrides via
    /// `with_hot_topics_config`.
    hot_topics_config: crate::config::HotTopicsConfig,
}

/// Rejection reason for step 4d (tiered identity). Shared with
/// `network::handle_gossip_message`, which pattern-matches on this exact
/// text to decide whether a `Rejected` result is a routine policy denial
/// (debug!) or a chain-scan-lag signal worth surfacing at warn! — keep both
/// sites on this constant so the two never drift apart.
pub const REGISTRATION_REQUIRED_REASON: &str =
    "on-chain registration required: verify your wallet to use this feature";

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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage: Storage,
        identity: IdentityResolver,
        pow: Option<Arc<crate::pow::PowManager>>,
        network: String,
        dm_recipient_cap: usize,
        counters: Arc<crate::metrics::counters::NetworkCounters>,
        rate_limits_config: crate::config::RateLimitsConfig,
    ) -> Self {
        Self {
            storage,
            identity,
            rate_limits: DashMap::new(),
            rate_limits_config,
            registration_cache: DashMap::new(),
            pow,
            network,
            dm_recipient_cap,
            dm_recipient_cap_lock: std::sync::Mutex::new(()),
            counters,
            hot_topics_config: crate::config::HotTopicsConfig::default(),
        }
    }

    /// Override the trending-hashtag aggregation policy (production wiring —
    /// tests keep the default). Builder-style so `new`'s already-long
    /// signature doesn't grow another argument.
    pub fn with_hot_topics_config(
        mut self,
        cfg: crate::config::HotTopicsConfig,
    ) -> Self {
        self.hot_topics_config = cfg;
        self
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

        // Step 2b: Reject envelope-pipeline-ineligible network types (Security
        // Audit follow-up, audit final pre-mainnet W8 removal). `Ping`/`Pong`/
        // `StateRoot`/`SyncRequest`/`SyncResponse` have no dedicated payload
        // type, no apply arm, and no legitimate reason to ever be
        // client-submitted or gossip-relayed as an `Envelope` — the real
        // ping/pong/sync mechanisms are separate libp2p protocols entirely
        // (`network::sync::SyncRequest` etc, NOT this MessageType). Before
        // this session, `SyncRequest` (0xF3) at least had to decode as the
        // narrow `ContentRequest` struct to pass validation; removing that
        // dead type (W8) left it — and its siblings, which already had this
        // gap — falling to the generic `Raw` catchall with NO payload shape
        // or size validation, `is_network()` making them exempt from
        // per-wallet rate limiting, and unconditional permanent storage on
        // `Accepted`. `NodeAnnouncement` (0xE0) is the ONLY `is_network()`
        // type with real handling (dedicated payload, apply arm) and is
        // deliberately NOT included here — this check is enumerated, not a
        // blanket `is_network()` reject, specifically so it doesn't break
        // legitimate NodeAnnouncement gossip relay.
        if matches!(
            envelope.msg_type,
            MessageType::Ping
                | MessageType::Pong
                | MessageType::StateRoot
                | MessageType::SyncRequest
                | MessageType::SyncResponse
        ) {
            return RouteResult::Invalid(format!(
                "{:?} is not a valid envelope-pipeline message type",
                envelope.msg_type
            ));
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
            // Audit final pre-mainnet W35: dedicated counter (isolated from
            // the broader `failed_validations` bucket) feeding the
            // `FailedSignatureSpike` alert.
            self.counters.inc_failed_signature_verifications();
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
            && !self.is_registered(&resolved_author)
        {
            return RouteResult::Rejected(REGISTRATION_REQUIRED_REASON.into());
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
            let registered = self.is_registered_cached(&resolved_author, now_ms);
            if self.is_rate_limited(&resolved_author, category, registered, now_ms) {
                // Code Audit NOTE #6: `HighRateLimitTriggers` (W35) only
                // observed HTTP-layer 429s (`GovernorLayer::error_handler`,
                // W36) — this router-level, per-wallet-per-category limit is
                // a separate, lower rejection point that counter never saw.
                // Same counter, so the alert's rate-delta check now reflects
                // both sources.
                self.counters.inc_rate_limited();
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

        // Step 7d2: Authorize DM reactions — reactor must be a participant of
        // the target DM conversation (audit W27 security follow-up).
        if let Err(e) = self.authorize_dm_reaction(&envelope, &resolved_author) {
            return RouteResult::Rejected(format!("dm_reaction_denied: {}", e));
        }

        // Step 7e: Read-only / broadcast channel enforcement — only creator and
        // moderators can post ChatMessage / ChatEdit / ChatDelete in ReadPublic
        // channels. Reactions remain open to all members. See protocol spec §3.6.
        if let Err(e) = self.check_readonly_channel(&envelope, &resolved_author) {
            return RouteResult::Rejected(format!("broadcast_channel_post_denied: {}", e));
        }

        // Step 7f (P4): an `encryption_enabled` channel rejects plaintext-text chat
        // (no-downgrade guarantee). Encrypted + attachment-only messages pass.
        if let Err(e) = self.check_channel_encryption_required(&envelope) {
            return RouteResult::Rejected(format!("channel_encryption_required: {}", e));
        }

        // Step 7g (audit final pre-mainnet W11): per-recipient DM storage cap.
        // Atomically checks AND reserves (increments) the slot — see
        // `reserve_dm_recipient_slot` doc for why check-then-later-increment
        // was a TOCTOU race under concurrent requests. Rejects rather than
        // evicts. Must run BEFORE Step 8's unconditional store, or a
        // rejected message would still consume disk as an orphaned,
        // unindexed MESSAGES row.
        if let Err(e) = self.reserve_dm_recipient_slot(&envelope) {
            return RouteResult::Rejected(format!("dm_recipient_cap_exceeded: {}", e));
        }

        // Step 8: Store message (atomically increments total_messages counter)
        if let Err(e) = self.storage.store_message(&envelope.msg_id, raw_bytes) {
            // Roll back the Step 7g reservation — the message was never
            // actually stored, so it must not count against the recipient's
            // cap (W11 Security Audit follow-up).
            if envelope.msg_type == MessageType::DirectMessage {
                if let Ok(payload) =
                    rmp_serde::from_slice::<DirectMessagePayload>(&envelope.payload)
                {
                    let _ = self
                        .storage
                        .decrement_dm_recipient_count(payload.recipient.as_bytes());
                }
            }
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
            &self.network,
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
            &self.network,
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
    /// `ogmara-device-claim:{network}:{device_pub_key_lowercase}:{wallet}:{timestamp}`
    /// in Klever message format (`network` folded in per audit 2026-08-16 C1
    /// follow-up — this claim's signature is the sole authority and never
    /// covers `msg_id`, so it needs its own network binding):
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
        // two signers signed are reproduced exactly on every node. Network-
        // bound (audit 2026-08-16 C1 follow-up): this claim's signature is
        // the SOLE authority here (msg_id equality alone proves nothing — it
        // is a public hash, not a MAC, and this claim scheme never covers
        // msg_id), so without `self.network` in the claim itself a captured
        // testnet claim would re-verify unchanged on mainnet.
        let device_pubkey_hex = payload.device_pub_key.to_ascii_lowercase();
        let claim = format!(
            "ogmara-device-claim:{}:{}:{}:{}",
            self.network, device_pubkey_hex, envelope.author, envelope.timestamp
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
    ///   * bind:   `ogmara-enc-bind:{network}:{enc_pub_lc}:{device_id_lc}:{wallet}:{timestamp}`
    ///   * revoke: `ogmara-enc-revoke:{network}:{enc_pub_lc}:{wallet}:{timestamp}`
    /// No device co-signature: an X25519 encryption key cannot produce a signature,
    /// and the wallet signature is the sole authority (binding a key the wallet does
    /// not control only harms that wallet). `network` is folded in (audit 2026-08-16
    /// C1 follow-up) for the same reason as `verify_device_delegation_claim`: this
    /// claim's signature is the sole authority and never covers `msg_id`.
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
                    "ogmara-enc-bind:{}:{}:{}:{}:{}",
                    self.network,
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
                    "ogmara-enc-revoke:{}:{}:{}:{}",
                    self.network,
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
    ///
    /// Audit final pre-mainnet W15 note: this 256-row prefix scan is NOT ordered by
    /// recency — `DEVICE_ENC_KEYS` keys embed `enc_pub` directly with no timestamp, so
    /// `prefix_iter_cf` returns whichever 256 rows sort lexicographically first,
    /// unrelated to age. If a wallet's TOTAL row count (active + tombstoned) ever
    /// exceeds 256, this scan (and `plan_enc_key_supersede`'s identical one) could
    /// silently miss real active/stale rows. Not independently hardened here (e.g. via
    /// a maintained counter CF) because the DeviceEnc rate limit (10/hour, was 100/min)
    /// plus the tombstone reaper (`reap_device_enc_tombstones`, `node.rs`) together
    /// keep any wallet's realistic total row count far below 256 under both normal use
    /// and the new, much lower abuse ceiling — this comment documents that dependency
    /// so a future change to either doesn't silently reopen the 256-row blind spot.
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
            &self.network,
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
    /// Applies both the burst and sustained windows (rate-limit rework,
    /// l2-node 0.122.0) — a request is limited if EITHER window is already
    /// at its cap. Does NOT increment the counters on a rejection, so a
    /// retry storm against an exhausted budget cannot inflate the stored
    /// count — only accepted messages consume budget.
    fn is_rate_limited(
        &self,
        author: &str,
        category: RateCategory,
        registered: bool,
        now_ms: u64,
    ) -> bool {
        let limits = category.limits(registered, &self.rate_limits_config);
        let key = format!("{}:{:?}", author, category);

        let mut entry = self.rate_limits.entry(key).or_insert(RateLimitEntry {
            burst_count: 0,
            burst_window_start: now_ms,
            sustained_count: 0,
            sustained_window_start: now_ms,
        });

        // Reset each window independently if expired.
        if now_ms.saturating_sub(entry.burst_window_start) > limits.burst_window_ms {
            entry.burst_count = 0;
            entry.burst_window_start = now_ms;
        }
        if now_ms.saturating_sub(entry.sustained_window_start) > limits.sustained_window_ms {
            entry.sustained_count = 0;
            entry.sustained_window_start = now_ms;
        }

        if entry.burst_count >= limits.burst_max || entry.sustained_count >= limits.sustained_max {
            return true;
        }

        entry.burst_count += 1;
        entry.sustained_count += 1;
        false
    }

    /// Whether `author` (a wallet address) is on-chain registered
    /// (`registered_at > 0` in the USERS record, written by the chain
    /// scanner — not by a mere `ProfileUpdate`). Uncached direct storage
    /// read — used by permission gates (step 4d, the `NewsEdit`
    /// defense-in-depth check) where a stale "not yet registered" result
    /// would incorrectly reject a message the wallet is now entitled to
    /// send. For the rate-limiter's hot path, use `is_registered_cached`
    /// instead.
    fn is_registered(&self, author: &str) -> bool {
        self.storage
            .get_cf(crate::storage::schema::cf::USERS, author.as_bytes())
            .ok()
            .flatten()
            .and_then(|data| serde_json::from_slice::<serde_json::Value>(&data).ok())
            .and_then(|v| v.get("registered_at")?.as_u64())
            .map_or(false, |ts| ts > 0)
    }

    /// Cached wrapper around `is_registered`, for the rate-limiter's tiering
    /// lookup (Step 6 runs on every rate-limited message, unlike step 4d's
    /// gate which only runs for the smaller set of `requires_verified_identity`
    /// types). See `REGISTRATION_CACHE_TTL_MS`.
    fn is_registered_cached(&self, author: &str, now_ms: u64) -> bool {
        if let Some(entry) = self.registration_cache.get(author) {
            let (registered, cached_at) = *entry;
            if now_ms.saturating_sub(cached_at) < REGISTRATION_CACHE_TTL_MS {
                return registered;
            }
        }
        let registered = self.is_registered(author);
        self.registration_cache
            .insert(author.to_string(), (registered, now_ms));
        registered
    }

    /// Evict expired rate limit / registration cache entries to prevent
    /// unbounded memory growth. Should be called periodically (e.g., every
    /// few minutes).
    ///
    /// Retains a `RateLimitEntry` while EITHER of its two windows is still
    /// live — with a single window this was a one-line threshold, but
    /// checking only one of the two independently-resetting windows here
    /// would evict (and silently reset) a budget whose OTHER window is
    /// still meaningfully populated (rate-limit rework, l2-node 0.122.0).
    pub fn cleanup_rate_limits(&self) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Largest window across all categories/tiers (NewsPost and
        // ModeratorChange sustained windows are both 1 day).
        const MAX_WINDOW_MS: u64 = 86_400_000;
        self.rate_limits.retain(|_, entry| {
            now_ms.saturating_sub(entry.burst_window_start) < MAX_WINDOW_MS
                || now_ms.saturating_sub(entry.sustained_window_start) < MAX_WINDOW_MS
        });
        self.registration_cache
            .retain(|_, (_, cached_at)| now_ms.saturating_sub(*cached_at) < MAX_WINDOW_MS);
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
                DeserializedPayload::ChannelUnmute(ref p) => {
                    validation::validate_channel_unmute(p)
                }
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
                DeserializedPayload::DirectMessage(ref p) => {
                    validation::validate_direct_message(resolved_author, p)
                }
                DeserializedPayload::SettingsSync(ref p) => {
                    validation::validate_settings_sync(p)
                }
                DeserializedPayload::KeyVaultSync(ref p) => {
                    validation::validate_key_vault_sync(p)
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
    /// P4: enforce that a channel marked `encryption_enabled` does not accept a
    /// PLAINTEXT-text `ChatMessage` (a downgrade that would leak content in a
    /// channel whose whole point is anti-bulk-readout). Attachment-only messages
    /// (empty `content`, no `enc_content`) and properly-encrypted messages
    /// (`enc_content` present) are allowed; attachments aren't encrypted until P5.
    /// Legacy channels (no `encryption_enabled` flag) are unaffected (dual-read).
    /// Only gates `ChatMessage` (edits carry their own enc fields, validated in
    /// `validate_dm_edit`/chat-edit; deletes carry no content).
    fn check_channel_encryption_required(&self, envelope: &Envelope) -> Result<(), String> {
        if envelope.msg_type != MessageType::ChatMessage {
            return Ok(());
        }
        let payload = match rmp_serde::from_slice::<ChatMessagePayload>(&envelope.payload) {
            Ok(p) => p,
            Err(_) => return Ok(()), // malformed → let validation reject it
        };
        // Fast path: an encrypted message (`enc_content` present) or one with no
        // plaintext text (attachment-only / empty) is ALWAYS allowed — skip the
        // channel-record read entirely. Only a plaintext-text message needs the
        // per-channel `encryption_enabled` check below.
        if payload.enc_content.is_some() || payload.content.is_empty() {
            return Ok(());
        }
        let key = payload.channel_id.to_be_bytes();
        let data = match self.storage.get_cf(schema::cf::CHANNELS, &key) {
            Ok(Some(d)) => d,
            _ => return Ok(()), // unknown/corrupt channel → not our gate
        };
        let meta: serde_json::Value = match serde_json::from_slice(&data) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        let encrypted = meta
            .get("encryption_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if encrypted && payload.enc_content.is_none() && !payload.content.is_empty() {
            return Err(format!(
                "channel {} is encrypted; plaintext content is not accepted",
                payload.channel_id
            ));
        }
        Ok(())
    }

    /// Per-recipient DM storage cap (audit final pre-mainnet W11). Only gates
    /// `DirectMessage` (edits/deletes/reactions don't grow `DM_MESSAGES`).
    /// Atomically CHECKS the cap and, if under it, immediately INCREMENTS
    /// the counter — both under `dm_recipient_cap_lock` — rather than
    /// checking here and incrementing later in `update_indexes` (Security
    /// Audit follow-up: `process_message` runs concurrently across Axum
    /// handlers against one shared `MessageRouter`/`Storage`, and
    /// `Storage::increment_dm_recipient_count` is a plain read-then-write,
    /// not an atomic RMW — a separate check-then-later-increment left a
    /// TOCTOU window where concurrent `DirectMessage`s to the same
    /// recipient could all pass the check before any of them incremented,
    /// overshooting the cap, repeatably, per burst of concurrency). If a
    /// LATER step rejects the envelope (e.g. Step 8's storage write fails),
    /// the caller must roll back this reservation — see the `store_message`
    /// error path below.
    ///
    /// Deliberately REJECTS the new message rather than evicting the
    /// recipient's oldest stored one: `DirectMessagePayload.recipient` is an
    /// unauthenticated, sender-chosen field (never checked against the
    /// sender's actual authority to address that wallet), so an evict-oldest
    /// cap would let a single PoW-solved attacker wallet — subject only to
    /// the existing PER-SENDER 30/min rate limit, not a per-recipient one —
    /// address a stream of throwaway DMs at a real victim and permanently
    /// evict the victim's genuine DM history forever. That would recreate
    /// this exact finding's own LRU-eviction-attack shape one layer down,
    /// inside the very fix meant to close it. Rejecting instead means the
    /// attacker's own spam simply stops landing once the victim is at cap;
    /// nothing the victim already has is ever destroyed. Trade-off: a
    /// legitimate wallet that receives more than the cap's worth of DMs
    /// within `retention_days` before the reaper frees space also sees new
    /// DMs rejected — acceptable given the cap (default 2000) is set well
    /// above organic single-recipient volume.
    fn reserve_dm_recipient_slot(&self, envelope: &Envelope) -> Result<(), String> {
        if envelope.msg_type != MessageType::DirectMessage || self.dm_recipient_cap == 0 {
            return Ok(());
        }
        let payload = match rmp_serde::from_slice::<DirectMessagePayload>(&envelope.payload) {
            Ok(p) => p,
            Err(_) => return Ok(()), // malformed → let validation reject it
        };
        let _guard = self
            .dm_recipient_cap_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = self
            .storage
            .get_dm_recipient_count(payload.recipient.as_bytes())
            .unwrap_or(0);
        if count >= self.dm_recipient_cap as u64 {
            return Err(format!(
                "recipient {} has reached the max stored DM count ({})",
                payload.recipient, self.dm_recipient_cap
            ));
        }
        let _ = self
            .storage
            .increment_dm_recipient_count(payload.recipient.as_bytes());
        Ok(())
        // `_guard` drops here, releasing the lock.
    }

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
            // Creator-only: deleting the channel. A channel this node has never seen
            // locally (out-of-order gossip / chain-scan lag, audit final pre-mainnet
            // W14) is deliberately let through here rather than rejected — creator
            // identity can't be checked until the channel actually exists, so
            // `update_indexes` defers by recording a pending claim instead of
            // authorizing the delete outright. See `channel_creator_check`.
            MessageType::ChannelDelete => {
                let channel_id = self
                    .extract_channel_id(envelope)
                    .ok_or("missing or invalid channel_id")?;
                match self.channel_creator_check(channel_id, resolved_author)? {
                    ChannelCreatorCheck::IsCreator | ChannelCreatorCheck::Unknown => Ok(()),
                    ChannelCreatorCheck::NotCreator => {
                        Err("only the channel creator can delete the channel".into())
                    }
                }
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
            // Reverses ChannelMute (audit W30). Reuses can_mute — no separate
            // can_unmute permission, same pattern as ChannelUnban reusing
            // can_ban. No creator-check needed: the creator can never have a
            // CHANNEL_MUTES entry in the first place (blocked above), so
            // unmuting them is always a harmless no-op delete.
            MessageType::ChannelUnmute => {
                let channel_id = self
                    .extract_channel_id(envelope)
                    .ok_or("missing or invalid channel_id")?;
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
                        // P2d hardening (C1): cap how far ahead of the current max epoch
                        // a key may be published, so a member can't wedge the channel by
                        // publishing at a near-u64::MAX epoch (which would saturate the
                        // rotation floor → permanently unsendable).
                        let max_epoch = self
                            .storage
                            .max_channel_key_epoch(&expected)
                            .map_err(|e| format!("storage error checking epoch: {}", e))?;
                        if p.epoch > max_epoch.saturating_add(CHANNEL_KEY_EPOCH_MAX_JUMP) {
                            return Err("channel key epoch too far ahead of the current epoch".into());
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
        if envelope.msg_type == MessageType::NewsEdit && !self.is_registered(resolved_author) {
            return Err("news edits require on-chain registration".into());
        }

        Ok(())
    }

    /// Authorize `DirectMessageReaction` (audit final pre-mainnet W27,
    /// security-audit follow-up): reject unless `resolved_author` is a
    /// participant (sender or recipient) of the DM conversation the target
    /// message belongs to.
    ///
    /// Without this, `toggle_chat_reaction` (reused from `ChatReaction` for
    /// DM reactions since W27) would index — and now, since W27 also added
    /// the gossip-bridge arm, RELAY to the real participants' nodes — a
    /// reaction from a wallet with no relationship to the conversation at
    /// all. DM `msg_id`s are not participant-secret: envelope headers
    /// (`author`, `msg_id`, `timestamp`) are plaintext even though `content`
    /// is E2E-encrypted, and DM-topic gossip subscription is unauthenticated,
    /// so any wallet that lurks on a target's DM topic can observe a real
    /// `msg_id` to forge a reaction against. `ChatReaction`/`NewsReaction`
    /// intentionally have no equivalent check — channel/news reactions are a
    /// many-to-many social feature where any member reacting to any message
    /// in the channel is the intended model — but a DM is strictly
    /// two-party, so an unrelated wallet's reaction appearing in it is a
    /// privacy/integrity violation, not just a permissive default.
    fn authorize_dm_reaction(
        &self,
        envelope: &Envelope,
        resolved_author: &str,
    ) -> Result<(), String> {
        if envelope.msg_type != MessageType::DirectMessageReaction {
            return Ok(());
        }
        let payload = rmp_serde::from_slice::<ReactionPayload>(&envelope.payload)
            .map_err(|e| format!("failed to deserialize reaction payload: {}", e))?;

        let original_bytes = self
            .storage
            .get_cf(schema::cf::MESSAGES, &payload.target_id)
            .map_err(|e| format!("storage error: {}", e))?
            .ok_or_else(|| "target message not found".to_string())?;
        let original_envelope: Envelope = rmp_serde::from_slice(&original_bytes)
            .map_err(|e| format!("failed to deserialize original message: {}", e))?;
        if original_envelope.msg_type != MessageType::DirectMessage {
            return Err("target is not a direct message".into());
        }
        let dm_payload = rmp_serde::from_slice::<DirectMessagePayload>(&original_envelope.payload)
            .map_err(|e| format!("failed to deserialize original DM payload: {}", e))?;
        let original_sender = self
            .identity
            .resolve(&original_envelope.author)
            .map_err(|e| format!("failed to resolve original DM sender: {}", e))?;

        if resolved_author != original_sender && resolved_author != dm_payload.recipient {
            return Err("only DM conversation participants can react to this message".into());
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
            MessageType::ChannelDelete => {
                rmp_serde::from_slice::<ChannelDeletePayload>(&envelope.payload)
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
            MessageType::ChannelUnmute => {
                rmp_serde::from_slice::<ChannelUnmutePayload>(&envelope.payload)
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

    /// Same lookup as `is_channel_creator`, but distinguishes "the channel doesn't
    /// exist locally yet" from "it exists and `address` isn't the creator" instead of
    /// folding both into one error (audit final pre-mainnet W14) — callers that need to
    /// defer rather than hard-reject on the former (currently just `ChannelDelete`'s
    /// authorization) need that distinction. `is_channel_creator` is left as-is for its
    /// other call sites, which all want the existing hard-error-on-unknown behavior.
    fn channel_creator_check(
        &self,
        channel_id: u64,
        address: &str,
    ) -> Result<ChannelCreatorCheck, String> {
        match self.storage.get_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes()) {
            Ok(Some(data)) => Ok(match serde_json::from_slice::<serde_json::Value>(&data) {
                Ok(meta) if meta.get("creator").and_then(|v| v.as_str()) == Some(address) => {
                    ChannelCreatorCheck::IsCreator
                }
                _ => ChannelCreatorCheck::NotCreator,
            }),
            Ok(None) => Ok(ChannelCreatorCheck::Unknown),
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

    // Audit final pre-mainnet W18: channel membership add/remove + the P2d
    // key-epoch-floor raise used to live here as 3 separate unbatched,
    // unlocked RMWs of the same `CHANNELS` row. Moved into
    // `Storage::add_channel_member` / `Storage::remove_channel_member_and_
    // raise_epoch_floor` (storage/rocks.rs) as one lock-guarded, batched
    // operation each — see those doc comments for the failure scenario this
    // closes (a crash between member-removal and floor-raise permanently
    // defeated P2d forward secrecy for the removed member).

    /// Resolve a DM's `conversation_id` from its `target_id` (msg_id) by
    /// looking up the original `DirectMessage` envelope. Used by
    /// `DirectMessageEdit`/`DirectMessageDelete` indexing (audit final
    /// pre-mainnet W6): `EditPayload`/`DeletePayload` carry no
    /// `conversation_id` field, only `target_id`, so the DM edit/delete
    /// side-index has to recover it the same way `authorize_edit_delete`
    /// already does. `None` on any lookup/decode failure — a defensive
    /// no-op (skip indexing), never a hard error, since `authorize_edit_delete`
    /// has already run by the time `update_indexes` is called and guarantees
    /// the target exists for a genuinely authorized edit/delete.
    fn resolve_dm_conversation_id(&self, target_id: &[u8; 32]) -> Option<[u8; 32]> {
        let raw = self.storage.get_cf(schema::cf::MESSAGES, target_id).ok().flatten()?;
        let original: Envelope = rmp_serde::from_slice(&raw).ok()?;
        let payload: DirectMessagePayload = rmp_serde::from_slice(&original.payload).ok()?;
        Some(payload.conversation_id)
    }

    /// Resolve a ChatEdit/ChatDelete's real `channel_id` from its `target_id`
    /// (msg_id) by looking up the original `ChatMessage` envelope, mirroring
    /// `resolve_dm_conversation_id`.
    ///
    /// Security-audit follow-up on W6 (2026-08-18): the original W6 fix keyed
    /// the `CHANNEL_EDIT_DELETE_MSGS` side-index off `EditPayload`/
    /// `DeletePayload::channel_id` directly — a field the AUTHOR controls and
    /// `authorize_edit_delete` never validates (it only checks author identity
    /// and edit-window, not that `channel_id` matches the target's real
    /// channel). Any wallet editing/deleting its own message could therefore
    /// put an arbitrary (or absent) `channel_id` in the payload: at best it
    /// pollutes a channel that message was never in; at worst — `channel_id:
    /// None` on a genuine delete — the marker is silently indexed nowhere,
    /// reproducing the exact "deleted content resurfaces on a backfilling
    /// node" bug W6 exists to close, for that one message. Deriving the
    /// channel_id from the original `ChatMessagePayload` instead (which is
    /// itself part of a SIGNED, already-accepted envelope — not attacker
    /// input at this point) closes both: the value can no longer be spoofed
    /// or omitted.
    fn resolve_chat_channel_id(&self, target_id: &[u8; 32]) -> Option<u64> {
        let raw = self.storage.get_cf(schema::cf::MESSAGES, target_id).ok().flatten()?;
        let original: Envelope = rmp_serde::from_slice(&raw).ok()?;
        let payload: ChatMessagePayload = rmp_serde::from_slice(&original.payload).ok()?;
        Some(payload.channel_id)
    }

    /// Add one `NewsPost` `msg_id` to this node's local HyperLogLog sketch
    /// for `(tag, bucket_hour)` in `HOT_TOPICS_LOCAL` (spec 3 §3.9).
    ///
    /// Honors `max_tracked_tags_per_bucket`: once a bucket already tracks
    /// that many distinct tags, a brand-new tag is dropped (tags already
    /// present keep counting) — this bounds write amplification from
    /// tag-spam. Read-modify-write: `NewsPost` ingest is low-rate, so no
    /// RocksDB merge operator is warranted.
    fn hot_topics_sketch_insert(
        &self,
        bucket_hour: u64,
        tag: &str,
        msg_id: &[u8; 32],
    ) -> Result<()> {
        let key = schema::encode_hot_topics_key(bucket_hour, tag);
        let existing = self.storage.get_cf(schema::cf::HOT_TOPICS_LOCAL, &key)?;
        if existing.is_none() {
            let cap = self.hot_topics_config.max_tracked_tags_per_bucket;
            let tracked = self.storage.count_prefix_cf(
                schema::cf::HOT_TOPICS_LOCAL,
                &bucket_hour.to_be_bytes(),
                cap.saturating_add(1),
            )?;
            if tracked as usize >= cap {
                return Ok(());
            }
        }
        let mut hll = existing
            .as_deref()
            .and_then(crate::hll::Hll::from_bytes)
            .unwrap_or_default();
        hll.insert(msg_id);
        self.storage
            .put_cf(schema::cf::HOT_TOPICS_LOCAL, &key, &hll.to_bytes())?;
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
                // Index the deletion too: a node that chain-discovers this channel
                // later reconciles its metadata envelopes and will pull the
                // ChannelDelete → apply the tombstone → not resurrect it.
                | MessageType::ChannelDelete
                // Index kick/ban too: a node that chain-discovers this channel (or
                // reconciles after a scan gap) must also learn about removals that
                // already happened, or it resurrects a member the rest of the
                // network has already removed.
                | MessageType::ChannelKick
                | MessageType::ChannelBan
                | MessageType::ChannelUnban
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
                    let _ = self.storage.add_channel_member(
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

                    // The recipient's stored-DM counter is bumped earlier,
                    // atomically with the cap check, by
                    // `reserve_dm_recipient_slot` (Step 7g in
                    // `process_message_inner`) — NOT here. Incrementing a
                    // second time in this arm would double-count every DM
                    // (W11 Security Audit follow-up: moved the increment to
                    // close a TOCTOU race between a separate check and a
                    // later increment).
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

                // Index by tags (canonical normalized form — protocol §3.5) and
                // feed the per-(tag, hour) Hot Topics HyperLogLog sketch.
                if let Ok(payload) =
                    rmp_serde::from_slice::<NewsPostPayload>(&envelope.payload)
                {
                    let norm = crate::util::normalize_tags_dedup(&payload.tags);
                    let bucket_hour =
                        envelope.timestamp / schema::HOT_TOPICS_BUCKET_MS;
                    let ht = &self.hot_topics_config;
                    // Only sketch a post whose bucket is (or could still be) in
                    // the rolling window — a very old backfilled post shouldn't
                    // resurrect a long-evicted bucket.
                    let sketch_this_bucket = ht.enabled && {
                        let now_hour = crate::util::now_ms()
                            / schema::HOT_TOPICS_BUCKET_MS;
                        let lo = now_hour.saturating_sub(
                            ht.window_hours + ht.eviction_slack_hours,
                        );
                        bucket_hour >= lo && bucket_hour <= now_hour + 1
                    };
                    for tag in &norm {
                        let tag_key = schema::encode_news_by_tag_key(
                            tag,
                            envelope.timestamp,
                            &envelope.msg_id,
                        );
                        self.storage
                            .put_cf(schema::cf::NEWS_BY_TAG, &tag_key, &[])?;
                        if sketch_this_bucket {
                            self.hot_topics_sketch_insert(
                                bucket_hour,
                                tag,
                                &envelope.msg_id,
                            )?;
                        }
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
                    // Tombstone guard: never (re)create a channel that was deleted.
                    // `ChannelDelete` removes the CHANNELS row, so a resurrection
                    // attempt would otherwise hit the new-record branch below and
                    // re-create the channel network-wide with the attacker as
                    // creator. The chain scanner makes the same check (scanner.rs);
                    // this closes the L2-envelope path. channel_id is fully
                    // attacker-controlled here, so this MUST gate creation.
                    if self.storage.exists_cf(schema::cf::DELETED_CHANNELS, &key).unwrap_or(false) {
                        debug!(
                            channel_id = payload.channel_id,
                            "ChannelCreate for tombstoned channel — ignoring (deleted)"
                        );
                        return Ok(());
                    }
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
                                    // P4: seed encryption flags on a chain-scanned
                                    // skeleton from the creator's L2 ChannelCreate.
                                    // `or_insert` keeps them IMMUTABLE — a later
                                    // ChannelCreate replay can't flip encryption off.
                                    let (enc_enabled, hist_vis) =
                                        channel_encryption_defaults(&payload);
                                    obj.entry("encryption_enabled")
                                        .or_insert(serde_json::json!(enc_enabled));
                                    obj.entry("history_visibility")
                                        .or_insert(serde_json::json!(hist_vis));
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
                        let (enc_enabled, hist_vis) = channel_encryption_defaults(&payload);
                        let meta = serde_json::json!({
                            "channel_id": payload.channel_id,
                            "slug": payload.slug,
                            "channel_type": payload.channel_type as u8,
                            "creator": resolved_author,
                            "created_at": envelope.timestamp,
                            "display_name": payload.display_name,
                            "description": payload.description,
                            "member_count": 0,
                            "encryption_enabled": enc_enabled,
                            "history_visibility": hist_vis,
                        });
                        let meta_bytes = serde_json::to_vec(&meta)
                            .context("serializing channel metadata")?;
                        // Code Audit WARNING #2 fix: the row write and the pending
                        // member-removal-claim replay must be ONE
                        // `channel_membership_lock`-guarded critical section — see
                        // `put_channel_and_replay_pending_member_removals`'s doc
                        // comment for the orphaned-claim race this closes.
                        self.storage
                            .put_channel_and_replay_pending_member_removals(
                                payload.channel_id,
                                &meta_bytes,
                            )?;
                        self.storage
                            .increment_stat(schema::state_keys::TOTAL_CHANNELS)?;

                        // Add creator as first member (increments member_count to 1)
                        let _ = self.storage.add_channel_member(
                            payload.channel_id,
                            resolved_author,
                            envelope.timestamp,
                            "creator",
                        );

                        // W14: this is the first time this channel_id's creator has
                        // become known on this node — consume any pending delete claim
                        // recorded while the channel was still unknown. A match means
                        // the real creator already asked to delete it (we just hadn't
                        // seen the create yet); converge straight to deleted instead of
                        // momentarily resurrecting it. A mismatch (or no claim) is a
                        // silent no-op — the claim is gone either way, one-shot.
                        if let Ok(claim) = self.storage.take_pending_channel_delete(payload.channel_id) {
                            if channel_delete_claim_matches(claim.as_ref(), resolved_author) {
                                self.storage
                                    .tombstone_channel(payload.channel_id, envelope.timestamp)?;
                            }
                        }
                    }
                }
            }
            MessageType::ChannelJoin => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelJoinPayload>(&envelope.payload)
                {
                    // Validates channel exists and is idempotent (skips if already member)
                    let _ = self.storage.add_channel_member(
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
                    // Atomic (W18): member-removal + P2d epoch-floor raise in one
                    // batched, lock-guarded write — a leaver must not read messages
                    // sent after they go.
                    self.storage.remove_channel_member_and_raise_epoch_floor(
                        payload.channel_id,
                        resolved_author,
                    )?;
                }
            }
            MessageType::ChannelDelete => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelDeletePayload>(&envelope.payload)
                {
                    // Re-check fresh rather than trusting the authorize_channel_action
                    // result blindly (W14): that check ran before this envelope was
                    // stored, and a concurrent message could have created the channel
                    // in between. IsCreator is the normal case (authorization already
                    // enforced on every ingest path, so tombstoning here is safe and
                    // idempotent). Unknown means the channel still doesn't exist —
                    // record a pending claim instead of a tombstone, consumed later by
                    // whichever creation path (L2 envelope or chain scan) sees the
                    // channel first. NotCreator/storage-error is defensive-only: authz
                    // should already have blocked NotCreator.
                    match self.channel_creator_check(payload.channel_id, resolved_author) {
                        Ok(ChannelCreatorCheck::IsCreator) => {
                            self.storage
                                .tombstone_channel(payload.channel_id, envelope.timestamp)?;
                        }
                        Ok(ChannelCreatorCheck::Unknown) => {
                            self.storage.put_pending_channel_delete(
                                payload.channel_id,
                                resolved_author,
                                envelope.timestamp,
                            )?;
                        }
                        Ok(ChannelCreatorCheck::NotCreator) | Err(_) => {}
                    }
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
                    // Side index for news-sync's ride-along. NewsComment and
                    // NewsRepost land in NEWS_FEED (they are timeline content);
                    // a reaction is not, so without this it appeared in no index
                    // that backfill walks and could only ever arrive by live
                    // gossip — permanently lost if that was missed. Same shape
                    // and rationale as NEWS_EDIT_DELETE above.
                    let key =
                        schema::encode_news_key(envelope.timestamp, &envelope.msg_id);
                    self.storage
                        .put_cf(schema::cf::NEWS_REACTION_MSGS, &key, &[])?;
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
                    // Atomic (W18): member-removal + P2d epoch-floor raise (so the
                    // kicked member can't read future messages) in one batched,
                    // lock-guarded write.
                    self.storage.remove_channel_member_and_raise_epoch_floor(
                        payload.channel_id,
                        &payload.target_user,
                    )?;
                }
            }
            MessageType::ChannelBan => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelBanPayload>(&envelope.payload)
                {
                    // Atomic (W18): member-removal (updates member_count) + P2d
                    // epoch-floor raise (so the banned member can't read future
                    // messages) in one batched, lock-guarded write.
                    self.storage.remove_channel_member_and_raise_epoch_floor(
                        payload.channel_id,
                        &payload.target_user,
                    )?;

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
                    // Audit final pre-mainnet W6: index into a side CF (never
                    // CHANNEL_MSGS itself — that's read directly by
                    // `GET /channel/messages` with no msg_type filter) so the
                    // channel-history reconcile can also ship this edit to a
                    // backfilling node, not just the original message.
                    //
                    // Security-audit follow-up: use `resolve_chat_channel_id`
                    // (the ORIGINAL message's own channel_id), NOT
                    // `payload.channel_id` — the latter is author-controlled
                    // and unvalidated by `authorize_edit_delete`, so trusting
                    // it would let an author spoof/omit the channel and
                    // silently evade this very index.
                    if let Some(cid) = self.resolve_chat_channel_id(&payload.target_id) {
                        let key = schema::encode_channel_msg_key(
                            cid,
                            envelope.timestamp,
                            &envelope.msg_id,
                        );
                        self.storage
                            .put_cf(schema::cf::CHANNEL_EDIT_DELETE_MSGS, &key, &[])?;
                    }
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
                    // Audit final pre-mainnet W6 + security-audit follow-up
                    // (see ChatEdit above): without this, "deleted for
                    // everyone" content is re-served forever by any
                    // fresh/cold-joining node, and using the verified
                    // original channel_id (not the author-controlled
                    // payload field) closes the spoof/omit evasion.
                    if let Some(cid) = self.resolve_chat_channel_id(&payload.target_id) {
                        let key = schema::encode_channel_msg_key(
                            cid,
                            envelope.timestamp,
                            &envelope.msg_id,
                        );
                        self.storage
                            .put_cf(schema::cf::CHANNEL_EDIT_DELETE_MSGS, &key, &[])?;
                    }
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
                    // Audit final pre-mainnet W6: side-CF index (never
                    // DM_MESSAGES itself — read directly by
                    // `GET /dm/messages` with no msg_type filter) so dm-sync
                    // can also ship this edit to a backfilling node.
                    // `EditPayload` has no `conversation_id` field, so it's
                    // recovered from the target DM's own payload.
                    if let Some(conv_id) = self.resolve_dm_conversation_id(&payload.target_id) {
                        let key = schema::encode_dm_msg_key(
                            &conv_id,
                            envelope.timestamp,
                            &envelope.msg_id,
                        );
                        self.storage
                            .put_cf(schema::cf::DM_EDIT_DELETE_MSGS, &key, &[])?;
                    }
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
                    // Audit final pre-mainnet W6 (see DirectMessageEdit above).
                    if let Some(conv_id) = self.resolve_dm_conversation_id(&payload.target_id) {
                        let key = schema::encode_dm_msg_key(
                            &conv_id,
                            envelope.timestamp,
                            &envelope.msg_id,
                        );
                        self.storage
                            .put_cf(schema::cf::DM_EDIT_DELETE_MSGS, &key, &[])?;
                    }
                }
            }
            // Audit final pre-mainnet W27: the prior comment here ("DM reactions
            // are end-to-end encrypted, can't parse emoji/target_id") was wrong —
            // `ReactionPayload.emoji`/`target_id` are plain fields, and sdk-js's
            // `dmReactionPayload` sends them unencrypted (same shape as
            // ChatReaction). The apply arm was simply empty, so a DM reaction was
            // accepted, stored in MESSAGES, and then silently dropped: never
            // indexed (same-node `GET /dm` couldn't show it either), never
            // gossiped (see the new bridge arm in routes.rs). `toggle_chat_reaction`
            // keys purely on `msg_id` (globally unique across chat/DM/news), so
            // it's safe to reuse for DM reactions without a new CF —
            // `enrich_message_json` (already called by `get_dm_messages`) already
            // reads through the same CF and will surface these for free.
            MessageType::DirectMessageReaction => {
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
            MessageType::NewsEdit => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<EditPayload>(&envelope.payload)
                {
                    self.storage.store_edit(
                        &payload.target_id,
                        envelope.timestamp,
                        &envelope.msg_id,
                    )?;
                    // Audit final pre-mainnet W6: News shares the identical
                    // gap Chat/DM had (see ChatEdit above) — side-CF index,
                    // never NEWS_FEED itself (`GET /api/v1/news` has no
                    // msg_type filter).
                    let key =
                        schema::encode_news_key(envelope.timestamp, &envelope.msg_id);
                    self.storage
                        .put_cf(schema::cf::NEWS_EDIT_DELETE, &key, &[])?;

                    // If the edit overlays a new `tags` set, re-index
                    // `NEWS_BY_TAG` for the ORIGINAL post so the `?tag=` /
                    // `?tags=` feed filter stays correct (the read-time
                    // projection already swaps the displayed tags; the index
                    // is separate). Hot Topics sketches are intentionally NOT
                    // touched — they are an approximate rolling counter and
                    // decrement-on-edit is a probe vector (spec 3 §3.9).
                    if let Some(new_tags) = &payload.tags {
                        if let Ok(Some(orig_raw)) = self
                            .storage
                            .get_cf(schema::cf::MESSAGES, &payload.target_id)
                        {
                            if let Ok(orig_env) =
                                rmp_serde::from_slice::<Envelope>(&orig_raw)
                            {
                                if orig_env.msg_type == MessageType::NewsPost {
                                    let old: std::collections::HashSet<String> =
                                        rmp_serde::from_slice::<NewsPostPayload>(
                                            &orig_env.payload,
                                        )
                                        .map(|p| {
                                            crate::util::normalize_tags_dedup(&p.tags)
                                                .into_iter()
                                                .collect()
                                        })
                                        .unwrap_or_default();
                                    let new: std::collections::HashSet<String> =
                                        crate::util::normalize_tags_dedup(new_tags)
                                            .into_iter()
                                            .collect();
                                    for gone in old.difference(&new) {
                                        let k = schema::encode_news_by_tag_key(
                                            gone,
                                            orig_env.timestamp,
                                            &payload.target_id,
                                        );
                                        self.storage
                                            .delete_cf(schema::cf::NEWS_BY_TAG, &k)?;
                                    }
                                    for added in new.difference(&old) {
                                        let k = schema::encode_news_by_tag_key(
                                            added,
                                            orig_env.timestamp,
                                            &payload.target_id,
                                        );
                                        self.storage.put_cf(
                                            schema::cf::NEWS_BY_TAG,
                                            &k,
                                            &[],
                                        )?;
                                    }
                                }
                            }
                        }
                    }
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
                    // Audit final pre-mainnet W6 (see NewsEdit above).
                    let key =
                        schema::encode_news_key(envelope.timestamp, &envelope.msg_id);
                    self.storage
                        .put_cf(schema::cf::NEWS_EDIT_DELETE, &key, &[])?;
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
            MessageType::KeyVaultSync => {
                // E2E P3 (protocol §2.5): store the wallet-encrypted key-recovery
                // vault. Opaque to the node; persisted as JSON so the owner can
                // retrieve {encrypted_vault, nonce, format_version} for restore.
                // Last-write-wins per wallet — only the verified signer can write
                // their own record (auth is the envelope signature).
                if let Ok(payload) =
                    rmp_serde::from_slice::<KeyVaultSyncPayload>(&envelope.payload)
                {
                    let json = serde_json::json!({
                        "encrypted_vault": payload.encrypted_vault,
                        "nonce": payload.nonce,
                        "format_version": payload.format_version,
                    });
                    self.storage.store_key_vault(
                        resolved_author,
                        json.to_string().as_bytes(),
                    )?;
                    debug!(author = %resolved_author, "Key vault synced");
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
                            // Purge the user's most sensitive per-account artifacts:
                            // the E2E key-recovery vault (all DM/channel content keys)
                            // and the encrypted settings blob. Local to this node;
                            // other nodes purge as the DeletionRequest reaches them.
                            // (Security audit 2026-06-14, Sec-W1.)
                            self.storage.delete_key_vault(resolved_author)?;
                            self.storage.delete_settings(resolved_author)?;
                            warn!(
                                author = %resolved_author,
                                news_posts_marked = deleted_count,
                                "AllUserContent deletion: marked news posts, purged key \
                                 vault + settings. Channel message deletion is not yet \
                                 implemented."
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
            // Reverses ChannelMute (audit W30). `remove_channel_mute` already
            // existed (RocksDB delete_cf on CHANNEL_MUTES) but had zero
            // callers — a permanent mute (duration_secs: 0) was literally
            // irrevocable. Idempotent: deleting an already-absent key is a
            // no-op, not an error.
            MessageType::ChannelUnmute => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelUnmutePayload>(&envelope.payload)
                {
                    self.storage
                        .remove_channel_mute(payload.channel_id, &payload.target_user)?;
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
        (
            MessageRouter::new(storage, identity, None, "testnet".to_string(), usize::MAX, std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()), crate::config::RateLimitsConfig::default()),
            dir,
        )
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

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Build a wallet-authored DeviceEncBinding envelope whose `msg_id` is
    /// computed for `msg_id_network` but whose claim (and thus signature) is
    /// computed for `claim_network` — simulating an attacker who captured a
    /// genuine envelope on `claim_network` and re-hashed only the (public,
    /// secret-free) msg_id for `msg_id_network` before replaying it there.
    fn mismatched_network_enc_binding_envelope(
        wallet_key: &ed25519_dalek::SigningKey,
        msg_id_network: &str,
        claim_network: &str,
        timestamp: u64,
    ) -> Vec<u8> {
        let wallet = crypto::pubkey_to_address(&wallet_key.verifying_key()).unwrap();
        let enc_pub = "aa".repeat(32);
        let device_id = "bb".repeat(32);
        let payload = DeviceEncBindingPayload {
            device_id: device_id.clone(),
            enc_pub: enc_pub.clone(),
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();

        let claim = format!(
            "ogmara-enc-bind:{}:{}:{}:{}:{}",
            claim_network, enc_pub, device_id, wallet, timestamp
        );
        let wallet_sig = signing::sign_klever_message(wallet_key, claim.as_bytes());

        let wallet_pubkey = wallet_key.verifying_key().to_bytes();
        let msg_id =
            crypto::compute_msg_id(msg_id_network, &wallet_pubkey, &payload_bytes, timestamp);

        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::DeviceEncBinding,
            msg_id,
            author: wallet,
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: wallet_sig.to_bytes().to_vec(),
            relay_path: vec![],
        };
        rmp_serde::to_vec_named(&envelope).unwrap()
    }

    fn mainnet_router() -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        (
            MessageRouter::new(storage, identity, None, "mainnet".to_string(), usize::MAX, std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()), crate::config::RateLimitsConfig::default()),
            dir,
        )
    }

    #[test]
    fn device_enc_binding_same_network_claim_accepted() {
        // Sanity baseline: msg_id and claim built for the SAME network as the
        // receiving router must be accepted.
        let (r, _d) = router(); // "testnet"
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let bytes = mismatched_network_enc_binding_envelope(&key, "testnet", "testnet", now_ms());
        assert!(matches!(r.process_message(&bytes), RouteResult::Accepted { .. }));
    }

    #[test]
    fn device_enc_binding_claim_forged_for_wrong_network_is_rejected() {
        // C1 follow-up regression: an attacker who captured a genuine
        // testnet DeviceEncBinding cannot force it onto mainnet merely by
        // re-hashing msg_id for "mainnet" — the claim string (and thus the
        // wallet signature covering it) is independently network-bound, so
        // the signature check must fail even though msg_id matches.
        let (r, _d) = mainnet_router();
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        // msg_id recomputed for "mainnet" (what verify_msg_id expects here),
        // but the claim — and therefore wallet_sig — was built for "testnet".
        let bytes = mismatched_network_enc_binding_envelope(&key, "mainnet", "testnet", now_ms());
        assert!(matches!(r.process_message(&bytes), RouteResult::Invalid(_)));
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

// --- Cross-node ChannelKick/ChannelBan enforcement (federation parity) ---
//
// Reproduces a live bug: a host node applies a ChannelBan cleanly, but a
// federated member node that received the SAME gossip envelope never applies
// it (member stays, CHANNEL_BANS never written, key_epoch_floor never
// raised). These tests simulate two independent node instances receiving the
// identical signed envelope via the real `process_message` pipeline, to
// determine whether the router logic itself diverges given identical state
// (it doesn't — see `ban_applies_when_both_nodes_fully_synced`), or whether
// divergent local state (specifically: the creator's on-chain registration
// record, checked by `requires_verified_identity()` in step 4d, *before*
// `authorize_channel_action`'s step-7c creator/mod check) causes a silent
// per-node rejection (it does — see the second test).
#[cfg(test)]
mod cross_node_ban_kick_tests {
    use super::*;
    use tempfile::TempDir;

    fn router() -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        (
            MessageRouter::new(storage, identity, None, "testnet".to_string(), usize::MAX, std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()), crate::config::RateLimitsConfig::default()),
            dir,
        )
    }

    fn make_channel(r: &MessageRouter, channel_id: u64, creator: &str) {
        let meta = serde_json::json!({
            "channel_id": channel_id,
            "channel_type": 2u8,
            "creator": creator,
            "member_count": 2u64,
        });
        r.storage
            .put_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes(), meta.to_string().as_bytes())
            .unwrap();
        add_member(r, channel_id, creator);
    }

    fn add_member(r: &MessageRouter, channel_id: u64, addr: &str) {
        let key = schema::encode_channel_member_key(channel_id, addr);
        r.storage.put_cf(schema::cf::CHANNEL_MEMBERS, &key, b"{}").unwrap();
    }

    fn register_user(r: &MessageRouter, address: &str, registered_at: u64) {
        let rec = serde_json::json!({ "address": address, "registered_at": registered_at });
        r.storage
            .put_cf(schema::cf::USERS, address.as_bytes(), rec.to_string().as_bytes())
            .unwrap();
    }

    /// Build a fully signed ChannelBan envelope (real msg_id + real Ed25519
    /// signature), ready to feed into `process_message` on any node.
    fn signed_ban_envelope(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        channel_id: u64,
        target_user: &str,
        timestamp: u64,
    ) -> Vec<u8> {
        let payload = ChannelBanPayload {
            channel_id,
            target_user: target_user.to_string(),
            reason: Some("test".into()),
            duration_secs: 0,
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id =
            crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ChannelBan as u8,
            &msg_id,
            timestamp,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChannelBan,
            msg_id,
            author: author.to_string(),
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        rmp_serde::to_vec_named(&envelope).unwrap()
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn ban_applies_identically_when_both_nodes_fully_synced() {
        let (host, _d1) = router();
        let (target_node, _d2) = router();

        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let banned = "klv1banneduser";
        let cid = 42u64;

        for r in [&host, &target_node] {
            make_channel(r, cid, &creator);
            add_member(r, cid, banned);
            register_user(r, &creator, 1_000);
        }

        let raw = signed_ban_envelope(&sk, &creator, cid, banned, now_ms());

        for r in [&host, &target_node] {
            match r.process_message(&raw) {
                RouteResult::Accepted { .. } => {}
                other => panic!("expected Accepted on fully-synced node, got {:?}", other),
            }
            let member_key = schema::encode_channel_member_key(cid, banned);
            assert!(
                r.storage.get_cf(schema::cf::CHANNEL_MEMBERS, &member_key).unwrap().is_none(),
                "banned member must be removed"
            );
            let ban_key = schema::encode_channel_ban_key(cid, banned);
            assert!(
                r.storage.get_cf(schema::cf::CHANNEL_BANS, &ban_key).unwrap().is_some(),
                "CHANNEL_BANS record must be written"
            );
        }
    }

    #[test]
    fn ban_silently_rejected_when_target_node_lacks_creator_registration() {
        let (host, _d1) = router();
        let (target_node, _d2) = router();

        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let banned = "klv1banneduser";
        let cid = 42u64;

        for r in [&host, &target_node] {
            make_channel(r, cid, &creator);
            add_member(r, cid, banned);
        }
        // Host's chain scanner has recorded the creator's on-chain registration;
        // the federated target node's local scanner has NOT (lagging/never
        // synced) — the exact divergence hypothesized as the live bug's cause.
        register_user(&host, &creator, 1_000);

        let raw = signed_ban_envelope(&sk, &creator, cid, banned, now_ms());

        assert!(matches!(host.process_message(&raw), RouteResult::Accepted { .. }));

        match target_node.process_message(&raw) {
            RouteResult::Rejected(reason) => {
                assert!(
                    reason.contains(REGISTRATION_REQUIRED_REASON),
                    "unexpected rejection reason: {reason}"
                );
            }
            other => panic!("expected Rejected(on-chain registration), got {:?}", other),
        }
        // Reproduces the live bug: the ban never applies on the target node —
        // member stays, CHANNEL_BANS is never written — even though the SAME
        // envelope that the host accepted was delivered via gossip.
        let member_key = schema::encode_channel_member_key(cid, banned);
        assert!(target_node.storage.get_cf(schema::cf::CHANNEL_MEMBERS, &member_key).unwrap().is_some());
        let ban_key = schema::encode_channel_ban_key(cid, banned);
        assert!(target_node.storage.get_cf(schema::cf::CHANNEL_BANS, &ban_key).unwrap().is_none());
    }
}

#[cfg(test)]
mod channel_delete_claim_matches_tests {
    //! Audit final pre-mainnet W14. Pure-fn unit tests for the shared
    //! matching logic both `update_indexes` (router.rs) and the chain
    //! scanner's `ChannelCreated` handler use to decide whether to honor a
    //! pending delete claim.
    use super::*;

    #[test]
    fn no_claim_never_matches() {
        assert!(!channel_delete_claim_matches(None, "klv1creator"));
    }

    #[test]
    fn matching_claimant_matches() {
        let claim = ("klv1creator".to_string(), 1_000);
        assert!(channel_delete_claim_matches(Some(&claim), "klv1creator"));
    }

    #[test]
    fn mismatched_claimant_does_not_match() {
        let claim = ("klv1attacker".to_string(), 1_000);
        assert!(!channel_delete_claim_matches(Some(&claim), "klv1creator"));
    }
}

#[cfg(test)]
mod channel_delete_before_create_tests {
    //! Audit final pre-mainnet W14: a `ChannelDelete` received before this
    //! node knows the channel (out-of-order gossip / chain-scan lag) must
    //! not be permanently lost, but also must never let a non-creator force
    //! a delete or block a legitimate future creation.
    use super::*;
    use tempfile::TempDir;

    fn router() -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        (
            MessageRouter::new(storage, identity, None, "testnet".to_string(), usize::MAX, std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()), crate::config::RateLimitsConfig::default()),
            dir,
        )
    }

    fn make_channel(r: &MessageRouter, channel_id: u64, creator: &str) {
        let meta = serde_json::json!({
            "channel_id": channel_id,
            "channel_type": 2u8,
            "creator": creator,
            "member_count": 1u64,
        });
        r.storage
            .put_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes(), meta.to_string().as_bytes())
            .unwrap();
    }

    fn register_user(r: &MessageRouter, address: &str, registered_at: u64) {
        let rec = serde_json::json!({ "address": address, "registered_at": registered_at });
        r.storage
            .put_cf(schema::cf::USERS, address.as_bytes(), rec.to_string().as_bytes())
            .unwrap();
    }

    fn signed_delete_envelope(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        channel_id: u64,
        timestamp: u64,
    ) -> Vec<u8> {
        let payload = ChannelDeletePayload { channel_id };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id =
            crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ChannelDelete as u8,
            &msg_id,
            timestamp,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChannelDelete,
            msg_id,
            author: author.to_string(),
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        rmp_serde::to_vec_named(&envelope).unwrap()
    }

    fn signed_create_envelope(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        channel_id: u64,
        slug: &str,
        timestamp: u64,
    ) -> Vec<u8> {
        let payload = ChannelCreatePayload {
            channel_id,
            slug: slug.to_string(),
            channel_type: ChannelType::Private,
            display_name: None,
            description: None,
            content_rating: Default::default(),
            moderation: ModerationPolicy { admins: vec![], rules: None },
            encryption_enabled: None,
            history_visibility: None,
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id =
            crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ChannelCreate as u8,
            &msg_id,
            timestamp,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChannelCreate,
            msg_id,
            author: author.to_string(),
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        rmp_serde::to_vec_named(&envelope).unwrap()
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    #[test]
    fn delete_for_unknown_channel_is_accepted_and_records_a_pending_claim() {
        let (r, _d) = router();
        let sk = crypto::generate_keypair();
        let claimant = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &claimant, 1_000);
        let cid = 4242u64;

        let raw = signed_delete_envelope(&sk, &claimant, cid, now_ms());
        match r.process_message(&raw) {
            RouteResult::Accepted { .. } => {}
            other => panic!("expected Accepted (deferred, not rejected), got {:?}", other),
        }
        assert!(
            r.storage.get_cf(schema::cf::PENDING_CHANNEL_DELETES, &cid.to_be_bytes()).unwrap().is_some(),
            "pending delete claim must be recorded"
        );
        assert!(
            r.storage.exists_cf(schema::cf::DELETED_CHANNELS, &cid.to_be_bytes()).unwrap_or(false) == false,
            "must not tombstone a channel it has never seen"
        );
    }

    #[test]
    fn later_create_by_same_wallet_converges_to_deleted() {
        let (r, _d) = router();
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);
        let cid = 4243u64;

        let delete_raw = signed_delete_envelope(&sk, &creator, cid, now_ms());
        assert!(matches!(r.process_message(&delete_raw), RouteResult::Accepted { .. }));

        let create_raw = signed_create_envelope(&sk, &creator, cid, "test-channel", now_ms() + 1);
        assert!(matches!(r.process_message(&create_raw), RouteResult::Accepted { .. }));

        assert!(
            r.storage.get_cf(schema::cf::CHANNELS, &cid.to_be_bytes()).unwrap().is_none(),
            "channel must converge to deleted, not resurrected"
        );
        assert!(
            r.storage.exists_cf(schema::cf::DELETED_CHANNELS, &cid.to_be_bytes()).unwrap_or(false),
            "tombstone must exist"
        );
        assert!(
            r.storage.get_cf(schema::cf::PENDING_CHANNEL_DELETES, &cid.to_be_bytes()).unwrap().is_none(),
            "claim must be consumed"
        );
    }

    #[test]
    fn later_create_by_different_wallet_is_not_deleted_and_claim_is_dropped() {
        let (r, _d) = router();
        let attacker_sk = crypto::generate_keypair();
        let attacker = crypto::pubkey_to_address(&attacker_sk.verifying_key()).unwrap();
        register_user(&r, &attacker, 1_000);
        let real_creator_sk = crypto::generate_keypair();
        let real_creator = crypto::pubkey_to_address(&real_creator_sk.verifying_key()).unwrap();
        register_user(&r, &real_creator, 1_000);
        let cid = 4244u64;

        // Attacker guesses the not-yet-used channel_id and claims to delete it.
        let delete_raw = signed_delete_envelope(&attacker_sk, &attacker, cid, now_ms());
        assert!(matches!(r.process_message(&delete_raw), RouteResult::Accepted { .. }));

        // The real creator later actually creates it.
        let create_raw =
            signed_create_envelope(&real_creator_sk, &real_creator, cid, "test-channel", now_ms() + 1);
        assert!(matches!(r.process_message(&create_raw), RouteResult::Accepted { .. }));

        assert!(
            r.storage.get_cf(schema::cf::CHANNELS, &cid.to_be_bytes()).unwrap().is_some(),
            "channel must be created normally — a mismatched claim must never block creation"
        );
        assert!(
            !r.storage.exists_cf(schema::cf::DELETED_CHANNELS, &cid.to_be_bytes()).unwrap_or(false),
            "must not be tombstoned — the claimant was never the real creator"
        );
        assert!(
            r.storage.get_cf(schema::cf::PENDING_CHANNEL_DELETES, &cid.to_be_bytes()).unwrap().is_none(),
            "the stale, non-matching claim must still be consumed (one-shot)"
        );
    }

    #[test]
    fn delete_for_existing_channel_by_non_creator_still_rejected() {
        let (r, _d) = router();
        let creator = "klv1realcreator";
        make_channel(&r, 4245, creator);
        let attacker_sk = crypto::generate_keypair();
        let attacker = crypto::pubkey_to_address(&attacker_sk.verifying_key()).unwrap();
        register_user(&r, &attacker, 1_000);

        let raw = signed_delete_envelope(&attacker_sk, &attacker, 4245, now_ms());
        match r.process_message(&raw) {
            RouteResult::Rejected(_) => {}
            other => panic!("expected Rejected, got {:?}", other),
        }
        assert!(!r.storage.exists_cf(schema::cf::DELETED_CHANNELS, &4245u64.to_be_bytes()).unwrap_or(false));
    }

    #[test]
    fn delete_for_existing_channel_by_creator_still_tombstones_immediately() {
        let (r, _d) = router();
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);
        make_channel(&r, 4246, &creator);

        let raw = signed_delete_envelope(&sk, &creator, 4246, now_ms());
        assert!(matches!(r.process_message(&raw), RouteResult::Accepted { .. }));
        assert!(r.storage.exists_cf(schema::cf::DELETED_CHANNELS, &4246u64.to_be_bytes()).unwrap_or(false));
        assert!(
            r.storage.get_cf(schema::cf::PENDING_CHANNEL_DELETES, &4246u64.to_be_bytes()).unwrap().is_none(),
            "the normal (non-deferred) path never touches the pending-claim CF"
        );
    }
}

#[cfg(test)]
mod dm_reaction_tests {
    use super::*;
    use tempfile::TempDir;

    fn router() -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        (
            MessageRouter::new(storage, identity, None, "testnet".to_string(), usize::MAX, std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()), crate::config::RateLimitsConfig::default()),
            dir,
        )
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    /// Store a genuine DM (sender -> recipient) directly in MESSAGES, bypassing
    /// full envelope signing (irrelevant to what `authorize_dm_reaction` reads
    /// — it only reads `original_envelope.author`/`msg_type` and the decoded
    /// `DirectMessagePayload.recipient`). Returns the DM's msg_id.
    fn store_dm(r: &MessageRouter, sender: &str, recipient: &str, msg_id: [u8; 32]) {
        let payload = DirectMessagePayload {
            recipient: recipient.to_string(),
            conversation_id: [7u8; 32],
            content: vec![1, 2, 3],
            nonce: [0u8; 24],
            key_epoch: 1,
            reply_to: None,
            attachments: vec![],
        };
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::DirectMessage,
            msg_id,
            author: sender.to_string(),
            timestamp: now_ms(),
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        r.storage
            .put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&envelope).unwrap())
            .unwrap();
    }

    /// Wire shape matches sdk-js's `dmReactionPayload`: `ReactionPayload`'s
    /// own fields plus a `recipient`/`conversation_id` the client sends
    /// alongside (routes.rs's bridge decodes `recipient` separately via
    /// `RecipientExtract`; the router only cares about `ReactionPayload`'s
    /// fields, which rmp-serde map-decoding ignores the extras for).
    #[derive(serde::Serialize)]
    struct WireDmReaction {
        target_id: [u8; 32],
        channel_id: Option<u64>,
        recipient: String,
        conversation_id: [u8; 32],
        emoji: String,
        remove: bool,
    }

    fn signed_dm_reaction_envelope(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        target_id: [u8; 32],
        emoji: &str,
        remove: bool,
        timestamp: u64,
    ) -> Vec<u8> {
        let payload = WireDmReaction {
            target_id,
            channel_id: None,
            recipient: "klv1recipient".to_string(),
            conversation_id: [7u8; 32],
            emoji: emoji.to_string(),
            remove,
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id =
            crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::DirectMessageReaction as u8,
            &msg_id,
            timestamp,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::DirectMessageReaction,
            msg_id,
            author: author.to_string(),
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        rmp_serde::to_vec_named(&envelope).unwrap()
    }

    #[test]
    fn dm_reaction_is_indexed_via_the_shared_chat_reaction_cf() {
        // Regression (audit final pre-mainnet W27): the apply arm was
        // `MessageType::DirectMessageReaction => {}` — accepted, stored in
        // MESSAGES, then silently dropped. `toggle_chat_reaction` keys purely
        // on `msg_id` (globally unique), so DM reactions can share the same
        // CF `enrich_message_json` already reads for chat messages — no new
        // schema needed. The reactor here is the DM's RECIPIENT (not the
        // original sender) — proves `authorize_dm_reaction` accepts either
        // participant, not just the original DM author.
        let (r, _dir) = router();
        let dm_sender = "klv1dmsender";
        let reactor_sk = crypto::generate_keypair();
        let reactor = crypto::pubkey_to_address(&reactor_sk.verifying_key()).unwrap();
        let target_id = [3u8; 32];
        store_dm(&r, dm_sender, &reactor, target_id);

        let raw =
            signed_dm_reaction_envelope(&reactor_sk, &reactor, target_id, "🔥", false, now_ms());
        match r.process_message(&raw) {
            RouteResult::Accepted { .. } => {}
            other => panic!("expected Accepted, got {:?}", other),
        }

        let reactions = r.storage.get_chat_reactions(&target_id).unwrap();
        assert_eq!(reactions, vec![("🔥".to_string(), 1)]);
    }

    #[test]
    fn dm_reaction_double_remove_does_not_underflow_the_count() {
        // Each remove below is a genuinely distinct signed envelope (different
        // timestamp/msg_id) — not a literal duplicate-relay (the router's
        // separate msg_id-dedup layer already handles that generically for
        // every type). This tests that `toggle_chat_reaction`'s own
        // remove-when-absent branch safely no-ops instead of underflowing
        // the saturating count, e.g. a double-tap "unreact" from the client.
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let target_id = [4u8; 32];
        store_dm(&r, &author, "klv1recipient", target_id);

        let add = signed_dm_reaction_envelope(&sk, &author, target_id, "👍", false, now_ms());
        assert!(matches!(r.process_message(&add), RouteResult::Accepted { .. }));

        let remove =
            signed_dm_reaction_envelope(&sk, &author, target_id, "👍", true, now_ms() + 1);
        assert!(matches!(r.process_message(&remove), RouteResult::Accepted { .. }));
        assert_eq!(r.storage.get_chat_reactions(&target_id).unwrap(), vec![]);

        let remove_again =
            signed_dm_reaction_envelope(&sk, &author, target_id, "👍", true, now_ms() + 2);
        assert!(matches!(r.process_message(&remove_again), RouteResult::Accepted { .. }));
        assert_eq!(r.storage.get_chat_reactions(&target_id).unwrap(), vec![]);
    }

    #[test]
    fn dm_reaction_from_a_non_participant_is_rejected() {
        // Security-audit follow-up finding on W27: without this check, ANY
        // wallet could inject a reaction into a DM conversation it has no
        // part in, and (since W27 also gossips DM reactions) that forgery
        // would relay to the real participants' nodes. `store_dm` makes
        // "klv1dmsender" -> "klv1dmrecipient" the only two legitimate
        // parties; a third wallet reacting to that msg_id must be rejected.
        let (r, _dir) = router();
        let target_id = [5u8; 32];
        store_dm(&r, "klv1dmsender", "klv1dmrecipient", target_id);

        let outsider_sk = crypto::generate_keypair();
        let outsider = crypto::pubkey_to_address(&outsider_sk.verifying_key()).unwrap();
        // signed_dm_reaction_envelope's hardcoded `recipient` field in the
        // WIRE payload is irrelevant to authorization — only the ORIGINAL
        // DM's stored sender/recipient matter, which the outsider is neither.
        let raw =
            signed_dm_reaction_envelope(&outsider_sk, &outsider, target_id, "🔥", false, now_ms());

        match r.process_message(&raw) {
            RouteResult::Rejected(reason) => {
                assert!(
                    reason.contains("dm_reaction_denied"),
                    "unexpected rejection reason: {reason}"
                );
            }
            other => panic!("expected Rejected(dm_reaction_denied), got {:?}", other),
        }
        assert_eq!(r.storage.get_chat_reactions(&target_id).unwrap(), vec![]);
    }

    #[test]
    fn dm_reaction_targeting_a_non_dm_message_is_rejected() {
        // Defense in depth: `target_id` must resolve to an ACTUAL
        // DirectMessage, not e.g. a ChatMessage id smuggled through the same
        // reaction path.
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let target_id = [6u8; 32];

        let chat_payload = ChatMessagePayload {
            channel_id: 1,
            content: "hi".to_string(),
            content_rating: Default::default(),
            reply_to: None,
            mentions: vec![],
            attachments: vec![],
            enc_content: None,
            enc_nonce: None,
            key_epoch: None,
        };
        let chat_envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChatMessage,
            msg_id: target_id,
            author: author.clone(),
            timestamp: now_ms(),
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&chat_payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        r.storage
            .put_cf(
                schema::cf::MESSAGES,
                &target_id,
                &rmp_serde::to_vec_named(&chat_envelope).unwrap(),
            )
            .unwrap();

        let raw = signed_dm_reaction_envelope(&sk, &author, target_id, "🔥", false, now_ms());
        match r.process_message(&raw) {
            RouteResult::Rejected(reason) => {
                assert!(reason.contains("not a direct message"), "unexpected reason: {reason}");
            }
            other => panic!("expected Rejected(not a direct message), got {:?}", other),
        }
    }
}

#[cfg(test)]
mod channel_mute_unmute_tests {
    use super::*;
    use tempfile::TempDir;

    fn router() -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        (
            MessageRouter::new(storage, identity, None, "testnet".to_string(), usize::MAX, std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()), crate::config::RateLimitsConfig::default()),
            dir,
        )
    }

    fn make_channel(r: &MessageRouter, channel_id: u64, creator: &str) {
        let meta = serde_json::json!({
            "channel_id": channel_id,
            "channel_type": 2u8,
            "creator": creator,
            "member_count": 2u64,
        });
        r.storage
            .put_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes(), meta.to_string().as_bytes())
            .unwrap();
        add_member(r, channel_id, creator);
    }

    fn add_member(r: &MessageRouter, channel_id: u64, addr: &str) {
        let key = schema::encode_channel_member_key(channel_id, addr);
        r.storage.put_cf(schema::cf::CHANNEL_MEMBERS, &key, b"{}").unwrap();
    }

    fn register_user(r: &MessageRouter, address: &str, registered_at: u64) {
        let rec = serde_json::json!({ "address": address, "registered_at": registered_at });
        r.storage
            .put_cf(schema::cf::USERS, address.as_bytes(), rec.to_string().as_bytes())
            .unwrap();
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    fn signed_mute_envelope(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        channel_id: u64,
        target_user: &str,
        duration_secs: u64,
        timestamp: u64,
    ) -> Vec<u8> {
        let payload = ChannelMutePayload {
            channel_id,
            target_user: target_user.to_string(),
            duration_secs,
            reason: Some("test".into()),
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id =
            crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ChannelMute as u8,
            &msg_id,
            timestamp,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChannelMute,
            msg_id,
            author: author.to_string(),
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        rmp_serde::to_vec_named(&envelope).unwrap()
    }

    fn signed_unmute_envelope(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        channel_id: u64,
        target_user: &str,
        timestamp: u64,
    ) -> Vec<u8> {
        let payload = ChannelUnmutePayload {
            channel_id,
            target_user: target_user.to_string(),
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id =
            crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ChannelUnmute as u8,
            &msg_id,
            timestamp,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChannelUnmute,
            msg_id,
            author: author.to_string(),
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        rmp_serde::to_vec_named(&envelope).unwrap()
    }

    #[test]
    fn permanent_mute_is_reversible_via_unmute() {
        // The literal W30 regression: before this fix, `duration_secs: 0`
        // ("permanent", per ChannelMutePayload's own doc comment) had NO
        // code path back — `remove_channel_mute` existed but had zero
        // callers. This test fails on pre-fix code (the mute would still
        // be active after the "unmute" envelope, since ChannelUnmute
        // didn't exist and the envelope would fail to even construct).
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let muted = "klv1muteduser";
        let cid = 42u64;
        make_channel(&r, cid, &creator);
        add_member(&r, cid, muted);
        register_user(&r, &creator, 1_000);

        let mute_raw = signed_mute_envelope(&sk, &creator, cid, muted, 0, now_ms());
        assert!(matches!(r.process_message(&mute_raw), RouteResult::Accepted { .. }));
        assert!(r.storage.is_channel_muted(cid, muted).unwrap(), "must be muted");

        let unmute_raw = signed_unmute_envelope(&sk, &creator, cid, muted, now_ms() + 1);
        match r.process_message(&unmute_raw) {
            RouteResult::Accepted { .. } => {}
            other => panic!("expected Accepted, got {:?}", other),
        }
        assert!(!r.storage.is_channel_muted(cid, muted).unwrap(), "must be unmuted");
    }

    #[test]
    fn unmute_rejected_without_can_mute_permission() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let muted = "klv1muteduser";
        let cid = 42u64;
        make_channel(&r, cid, &creator);
        add_member(&r, cid, muted);
        register_user(&r, &creator, 1_000);

        let mute_raw = signed_mute_envelope(&sk, &creator, cid, muted, 0, now_ms());
        assert!(matches!(r.process_message(&mute_raw), RouteResult::Accepted { .. }));

        // A random member with no moderator permissions tries to unmute.
        // Registered too, so the rejection is unambiguously about the
        // can_mute permission gate, not the separate registration gate.
        let outsider_sk = crypto::generate_keypair();
        let outsider = crypto::pubkey_to_address(&outsider_sk.verifying_key()).unwrap();
        add_member(&r, cid, &outsider);
        register_user(&r, &outsider, 1_000);
        let unmute_raw =
            signed_unmute_envelope(&outsider_sk, &outsider, cid, muted, now_ms() + 1);

        match r.process_message(&unmute_raw) {
            RouteResult::Rejected(reason) => {
                assert!(
                    reason.contains("unauthorized"),
                    "expected the authorization gate, not another rejection: {reason}"
                );
            }
            other => panic!("expected Rejected(unauthorized), got {:?}", other),
        }
        assert!(r.storage.is_channel_muted(cid, muted).unwrap(), "must remain muted");
    }

    #[test]
    fn unmute_of_never_muted_target_is_a_harmless_noop() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let target = "klv1nevermuted";
        let cid = 42u64;
        make_channel(&r, cid, &creator);
        add_member(&r, cid, target);
        register_user(&r, &creator, 1_000);

        let unmute_raw = signed_unmute_envelope(&sk, &creator, cid, target, now_ms());
        match r.process_message(&unmute_raw) {
            RouteResult::Accepted { .. } => {}
            other => panic!("expected Accepted (delete-of-missing-key is a no-op), got {:?}", other),
        }
        assert!(!r.storage.is_channel_muted(cid, target).unwrap());
    }

    #[test]
    fn unmute_idempotent_across_two_independent_nodes() {
        // Mirrors cross_node_ban_kick_tests's two-node pattern: the same
        // signed ChannelUnmute envelope applied on two independently-built
        // routers (simulating gossip delivery to both the origin node and
        // a relaying peer) must succeed cleanly on both, not error on the
        // second application.
        let (host, _d1) = router();
        let (peer, _d2) = router();

        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let muted = "klv1muteduser";
        let cid = 42u64;

        for r in [&host, &peer] {
            make_channel(r, cid, &creator);
            add_member(r, cid, muted);
            register_user(r, &creator, 1_000);
        }

        let mute_raw = signed_mute_envelope(&sk, &creator, cid, muted, 0, now_ms());
        for r in [&host, &peer] {
            assert!(matches!(r.process_message(&mute_raw), RouteResult::Accepted { .. }));
        }

        let unmute_raw = signed_unmute_envelope(&sk, &creator, cid, muted, now_ms() + 1);
        for r in [&host, &peer] {
            assert!(matches!(r.process_message(&unmute_raw), RouteResult::Accepted { .. }));
            assert!(!r.storage.is_channel_muted(cid, muted).unwrap());
        }
    }
}

#[cfg(test)]
mod edit_delete_index_tests {
    use super::*;
    use tempfile::TempDir;

    // Regression tests for audit final pre-mainnet W6: backfill previously
    // omitted edit/delete markers, so "deleted for everyone" content was
    // re-served forever by any fresh/cold-joining node. These verify the
    // producer side — that `update_indexes` writes the new side-CF row for
    // each of the six edit/delete types. The consumer side (reconcile/
    // dm-sync/news-sync ride-along) is tested in each protocol's own module.

    fn router() -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        (
            MessageRouter::new(storage, identity, None, "testnet".to_string(), usize::MAX, std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()), crate::config::RateLimitsConfig::default()),
            dir,
        )
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    fn register_user(r: &MessageRouter, address: &str, registered_at: u64) {
        let rec = serde_json::json!({ "address": address, "registered_at": registered_at });
        r.storage
            .put_cf(schema::cf::USERS, address.as_bytes(), rec.to_string().as_bytes())
            .unwrap();
    }

    /// Store a genuine ChatMessage directly in MESSAGES, bypassing full
    /// envelope signing (mirrors `dm_reaction_tests::store_dm` — irrelevant
    /// to what `authorize_edit_delete` reads, which is only
    /// `original_envelope.author`/`timestamp`).
    fn store_chat_message(r: &MessageRouter, author: &str, channel_id: u64, msg_id: [u8; 32], timestamp: u64) {
        let payload = ChatMessagePayload {
            channel_id,
            content: "hello".to_string(),
            content_rating: Default::default(),
            reply_to: None,
            mentions: vec![],
            attachments: vec![],
            enc_content: None,
            enc_nonce: None,
            key_epoch: None,
        };
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChatMessage,
            msg_id,
            author: author.to_string(),
            timestamp,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        r.storage
            .put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&envelope).unwrap())
            .unwrap();
    }

    /// Store a genuine DirectMessage directly in MESSAGES (mirrors
    /// `dm_reaction_tests::store_dm`, parameterized on `conversation_id` so
    /// the resolve-conversation-id lookup can be asserted against it).
    fn store_dm(
        r: &MessageRouter,
        sender: &str,
        recipient: &str,
        conversation_id: [u8; 32],
        msg_id: [u8; 32],
        timestamp: u64,
    ) {
        let payload = DirectMessagePayload {
            recipient: recipient.to_string(),
            conversation_id,
            content: vec![1, 2, 3],
            nonce: [0u8; 24],
            key_epoch: 1,
            reply_to: None,
            attachments: vec![],
        };
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::DirectMessage,
            msg_id,
            author: sender.to_string(),
            timestamp,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        r.storage
            .put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&envelope).unwrap())
            .unwrap();
    }

    /// Store a genuine NewsPost directly in MESSAGES.
    fn store_news_post(r: &MessageRouter, author: &str, msg_id: [u8; 32], timestamp: u64) {
        let payload = NewsPostPayload {
            title: "headline".to_string(),
            content: "body".to_string(),
            content_rating: Default::default(),
            tags: vec![],
            attachments: vec![],
            visibility: Default::default(),
        };
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::NewsPost,
            msg_id,
            author: author.to_string(),
            timestamp,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        r.storage
            .put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&envelope).unwrap())
            .unwrap();
    }

    /// Build a fully signed edit/delete envelope (real msg_id + real Ed25519
    /// signature), ready to feed into `process_message`.
    fn signed_edit_or_delete_envelope(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        msg_type: MessageType,
        target_id: [u8; 32],
        channel_id: Option<u64>,
        timestamp: u64,
    ) -> Vec<u8> {
        let payload_bytes = match msg_type {
            MessageType::ChatEdit | MessageType::DirectMessageEdit | MessageType::NewsEdit => {
                let payload = EditPayload {
                    target_id,
                    channel_id,
                    content: "edited".to_string(),
                    edited_at: timestamp,
                    title: None,
                    tags: None,
                    attachments: None,
                    // DM edits carry ciphertext, not plaintext content —
                    // `validate_dm_edit` requires it.
                    enc_content: matches!(msg_type, MessageType::DirectMessageEdit)
                        .then(|| vec![9u8, 9, 9]),
                    enc_nonce: None,
                    key_epoch: None,
                };
                rmp_serde::to_vec_named(&payload).unwrap()
            }
            MessageType::ChatDelete | MessageType::DirectMessageDelete | MessageType::NewsDelete => {
                let payload = DeletePayload { target_id, channel_id };
                rmp_serde::to_vec_named(&payload).unwrap()
            }
            _ => unreachable!("not an edit/delete type"),
        };
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id =
            crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            msg_type as u8,
            &msg_id,
            timestamp,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type,
            msg_id,
            author: author.to_string(),
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        rmp_serde::to_vec_named(&envelope).unwrap()
    }

    #[test]
    fn chat_edit_and_delete_are_indexed_into_the_side_cf() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000); // ChatEdit/ChatDelete are "advanced" (tiered identity)
        let channel_id = 42u64;
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        store_chat_message(&r, &author, channel_id, original_id, original_ts);

        let edit_ts = original_ts + 1;
        let edit_raw = signed_edit_or_delete_envelope(
            &sk, &author, MessageType::ChatEdit, original_id, Some(channel_id), edit_ts,
        );
        assert!(matches!(r.process_message(&edit_raw), RouteResult::Accepted { .. }));

        let delete_ts = original_ts + 2;
        let delete_raw = signed_edit_or_delete_envelope(
            &sk, &author, MessageType::ChatDelete, original_id, Some(channel_id), delete_ts,
        );
        assert!(matches!(r.process_message(&delete_raw), RouteResult::Accepted { .. }));

        let prefix = channel_id.to_be_bytes();
        let rows = r
            .storage
            .prefix_iter_cf(schema::cf::CHANNEL_EDIT_DELETE_MSGS, &prefix, 10)
            .unwrap();
        assert_eq!(rows.len(), 2, "expected both the edit and the delete indexed");
        // Keys are (channel_id, timestamp, msg_id) — ascending, so the edit
        // (earlier timestamp) sorts before the delete.
        let ts_of = |key: &[u8]| u64::from_be_bytes(key[8..16].try_into().unwrap());
        assert_eq!(ts_of(&rows[0].0), edit_ts);
        assert_eq!(ts_of(&rows[1].0), delete_ts);
    }

    #[test]
    fn dm_edit_and_delete_resolve_conversation_id_and_are_indexed() {
        // `EditPayload`/`DeletePayload` carry no `conversation_id` field —
        // this proves `resolve_dm_conversation_id` correctly recovers it
        // from the ORIGINAL DirectMessage's own payload.
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let sender = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &sender, 1_000); // DirectMessageDelete is "advanced" (tiered identity)
        let recipient = "klv1recipient";
        let conversation_id = [7u8; 32];
        let original_ts = now_ms();
        let original_id = [2u8; 32];
        store_dm(&r, &sender, recipient, conversation_id, original_id, original_ts);

        let delete_ts = original_ts + 1;
        let delete_raw = signed_edit_or_delete_envelope(
            &sk, &sender, MessageType::DirectMessageDelete, original_id, None, delete_ts,
        );
        assert!(matches!(r.process_message(&delete_raw), RouteResult::Accepted { .. }));

        let rows = r
            .storage
            .prefix_iter_cf(schema::cf::DM_EDIT_DELETE_MSGS, &conversation_id[..], 10)
            .unwrap();
        assert_eq!(rows.len(), 1);
        let ts = u64::from_be_bytes(rows[0].0[32..40].try_into().unwrap());
        assert_eq!(ts, delete_ts);
        let msg_id: [u8; 32] = rows[0].0[40..72].try_into().unwrap();
        assert_eq!(msg_id, {
            // Recompute the delete's own msg_id the same way the helper did.
            let pk: [u8; 32] = sk.verifying_key().to_bytes();
            let payload = DeletePayload { target_id: original_id, channel_id: None };
            let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
            crypto::compute_msg_id("testnet", &pk, &payload_bytes, delete_ts)
        });
    }

    #[test]
    fn news_edit_and_delete_are_indexed_into_the_side_cf() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000); // NewsEdit requires registration
        let original_ts = now_ms();
        let original_id = [3u8; 32];
        store_news_post(&r, &author, original_id, original_ts);

        let edit_ts = original_ts + 1;
        let edit_raw = signed_edit_or_delete_envelope(
            &sk, &author, MessageType::NewsEdit, original_id, None, edit_ts,
        );
        assert!(matches!(r.process_message(&edit_raw), RouteResult::Accepted { .. }));

        let delete_ts = original_ts + 2;
        let delete_raw = signed_edit_or_delete_envelope(
            &sk, &author, MessageType::NewsDelete, original_id, None, delete_ts,
        );
        assert!(matches!(r.process_message(&delete_raw), RouteResult::Accepted { .. }));

        let rows = r
            .storage
            .prefix_iter_cf(schema::cf::NEWS_EDIT_DELETE, &[], 10)
            .unwrap();
        assert_eq!(rows.len(), 2, "expected both the edit and the delete indexed");
    }

    #[test]
    fn chat_edit_indexes_under_the_real_channel_even_with_a_spoofed_payload_channel_id() {
        // Security-audit follow-up on W6: the original ChatMessage is in
        // channel 1, but the edit's OWN payload claims `channel_id: None`
        // (an author-controlled field `authorize_edit_delete` never
        // validates). Before the fix this silently skipped indexing
        // entirely — an author could omit or spoof the field to evade the
        // backfill index for their own delete/edit. The fix derives the
        // channel_id from the ORIGINAL message instead, so the row must
        // land under the REAL channel (1) regardless of what the payload
        // claims.
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let original_ts = now_ms();
        let original_id = [4u8; 32];
        let real_channel_id = 1u64;
        store_chat_message(&r, &author, real_channel_id, original_id, original_ts);

        let edit_raw = signed_edit_or_delete_envelope(
            &sk, &author, MessageType::ChatEdit, original_id, None, original_ts + 1,
        );
        assert!(matches!(r.process_message(&edit_raw), RouteResult::Accepted { .. }));

        let rows = r
            .storage
            .prefix_iter_cf(schema::cf::CHANNEL_EDIT_DELETE_MSGS, &real_channel_id.to_be_bytes(), 10)
            .unwrap();
        assert_eq!(rows.len(), 1, "must be indexed under the real channel despite the spoofed payload field");

        // A wrong (not just missing) channel_id in the payload must be
        // ignored too — a completely different channel (99) must NOT get a
        // row for this edit.
        let spoof_rows = r
            .storage
            .prefix_iter_cf(schema::cf::CHANNEL_EDIT_DELETE_MSGS, &99u64.to_be_bytes(), 10)
            .unwrap();
        assert!(spoof_rows.is_empty());
    }

    #[test]
    fn chat_edit_target_not_found_is_not_indexed() {
        // Defensive: if the original message lookup fails for any reason,
        // `resolve_chat_channel_id` returns `None` and indexing is simply
        // skipped — no panic, no garbage-keyed row.
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        // No `store_chat_message` call — the target genuinely doesn't
        // exist, so `authorize_edit_delete` itself rejects the envelope
        // before `update_indexes` ever runs.
        let missing_target = [42u8; 32];
        let edit_raw = signed_edit_or_delete_envelope(
            &sk, &author, MessageType::ChatEdit, missing_target, Some(1), now_ms(),
        );
        assert!(matches!(r.process_message(&edit_raw), RouteResult::Rejected(_)));

        let rows = r
            .storage
            .prefix_iter_cf(schema::cf::CHANNEL_EDIT_DELETE_MSGS, &1u64.to_be_bytes(), 10)
            .unwrap();
        assert!(rows.is_empty());
    }
}

#[cfg(test)]
mod dm_recipient_cap_tests {
    //! Audit final pre-mainnet W11: per-recipient DM storage cap.
    use super::*;
    use tempfile::TempDir;

    fn router_with_cap(cap: usize) -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        (
            MessageRouter::new(storage, identity, None, "testnet".to_string(), cap, std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()), crate::config::RateLimitsConfig::default()),
            dir,
        )
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    /// Full signed DirectMessage envelope, ready for `process_message` —
    /// unlike this module's sibling `store_dm` helpers (which write directly
    /// to MESSAGES for tests that only exercise post-storage logic), this
    /// one must pass the FULL pipeline (sig, dedup, rate limit, payload
    /// validation) to reach the new Step 7g cap check.
    fn signed_dm_envelope(
        sk: &ed25519_dalek::SigningKey,
        recipient: &str,
        timestamp: u64,
    ) -> Vec<u8> {
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let payload = DirectMessagePayload {
            recipient: recipient.to_string(),
            conversation_id: crypto::compute_conversation_id(&author, recipient),
            content: vec![1, 2, 3],
            nonce: [0u8; 24],
            key_epoch: 1,
            reply_to: None,
            attachments: vec![],
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::DirectMessage as u8,
            &msg_id,
            timestamp,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::DirectMessage,
            msg_id,
            author,
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        rmp_serde::to_vec_named(&envelope).unwrap()
    }

    #[test]
    fn dm_within_cap_is_accepted_and_increments_the_counter() {
        let (r, _dir) = router_with_cap(5);
        let sk = crypto::generate_keypair();
        let recipient = "klv1victim";
        let raw = signed_dm_envelope(&sk, recipient, now_ms());
        assert!(matches!(r.process_message(&raw), RouteResult::Accepted { .. }));
        assert_eq!(r.storage.get_dm_recipient_count(recipient.as_bytes()).unwrap(), 1);
    }

    #[test]
    fn dm_at_cap_is_rejected_not_evicted() {
        // The weaponization scenario this design explicitly guards against:
        // many DISTINCT throwaway senders (not rate-limited against each
        // other — the 30/min limit is per-sender) all naming the SAME
        // victim recipient. Once at cap, further DMs must be REJECTED, and
        // — critically — the victim's already-stored messages must survive
        // untouched (no eviction).
        let (r, _dir) = router_with_cap(3);
        let recipient = "klv1victim";
        let mut accepted_msg_ids = Vec::new();
        for i in 0..3u8 {
            let sk = crypto::generate_keypair();
            let raw = signed_dm_envelope(&sk, recipient, now_ms() + i as u64);
            match r.process_message(&raw) {
                RouteResult::Accepted { msg_id, .. } => accepted_msg_ids.push(msg_id),
                other => panic!("expected Accepted, got {other:?}"),
            }
        }
        assert_eq!(r.storage.get_dm_recipient_count(recipient.as_bytes()).unwrap(), 3);

        // A 4th distinct attacker wallet, still well under the per-sender
        // rate limit, must be rejected — not silently evicting one of the
        // 3 already-accepted messages.
        let attacker_sk = crypto::generate_keypair();
        let raw = signed_dm_envelope(&attacker_sk, recipient, now_ms() + 100);
        assert!(matches!(r.process_message(&raw), RouteResult::Rejected(reason) if reason.contains("dm_recipient_cap_exceeded")));
        assert_eq!(r.storage.get_dm_recipient_count(recipient.as_bytes()).unwrap(), 3, "cap rejection must not change the count");

        // Every one of the victim's genuine 3 messages must still be present.
        for msg_id in accepted_msg_ids {
            assert!(r.storage.get_cf(schema::cf::MESSAGES, &msg_id).unwrap().is_some(), "an existing stored message must never be evicted by the cap");
        }
    }

    #[test]
    fn cap_is_per_recipient_not_global() {
        let (r, _dir) = router_with_cap(1);
        let sk_a = crypto::generate_keypair();
        let sk_b = crypto::generate_keypair();
        let raw_a = signed_dm_envelope(&sk_a, "klv1alice", now_ms());
        let raw_b = signed_dm_envelope(&sk_b, "klv1bob", now_ms() + 1);
        assert!(matches!(r.process_message(&raw_a), RouteResult::Accepted { .. }));
        assert!(matches!(r.process_message(&raw_b), RouteResult::Accepted { .. }), "a different recipient must have its own independent budget");
    }

    #[test]
    fn zero_cap_means_unlimited() {
        let (r, _dir) = router_with_cap(0);
        let recipient = "klv1victim";
        for i in 0..5u8 {
            let sk = crypto::generate_keypair();
            let raw = signed_dm_envelope(&sk, recipient, now_ms() + i as u64);
            assert!(matches!(r.process_message(&raw), RouteResult::Accepted { .. }));
        }
    }

    #[test]
    fn concurrent_dms_to_the_same_recipient_never_overshoot_the_cap() {
        // Security Audit follow-up (W11): `reserve_dm_recipient_slot` must
        // check-and-increment atomically under `dm_recipient_cap_lock`. A
        // separate-check-then-later-increment design let concurrent
        // `DirectMessage`s to the same recipient all pass the check before
        // any of them incremented, overshooting the cap. Prove it holds
        // under REAL concurrency, not just sequential calls.
        let cap = 5usize;
        let (r, _dir) = router_with_cap(cap);
        let r = std::sync::Arc::new(r);
        let recipient = "klv1victim";
        let sks: Vec<_> = (0..40).map(|_| crypto::generate_keypair()).collect();

        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for (i, sk) in sks.iter().enumerate() {
                let r = r.clone();
                let accepted = accepted.clone();
                scope.spawn(move || {
                    let raw = signed_dm_envelope(sk, recipient, now_ms() + i as u64);
                    if matches!(r.process_message(&raw), RouteResult::Accepted { .. }) {
                        accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });

        assert_eq!(
            accepted.load(std::sync::atomic::Ordering::SeqCst),
            cap,
            "exactly `cap` DMs must be accepted, regardless of concurrency"
        );
        assert_eq!(
            r.storage.get_dm_recipient_count(recipient.as_bytes()).unwrap(),
            cap as u64,
            "the persisted counter must never exceed the cap under concurrent load"
        );
    }
}

#[cfg(test)]
mod rate_limit_counter_tests {
    //! Code Audit NOTE #6: the router's own Step 6 rate-limit rejection must
    //! increment the shared `NetworkCounters` — not just the HTTP-layer 429
    //! path (`GovernorLayer::error_handler`, W36) — so `HighRateLimitTriggers`
    //! (W35) sees both rejection sources, not only requests that never made
    //! it past the axum layer.
    use super::*;
    use tempfile::TempDir;

    fn router() -> (
        MessageRouter,
        TempDir,
        std::sync::Arc<crate::metrics::counters::NetworkCounters>,
    ) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        let counters = std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new());
        (
            MessageRouter::new(
                storage,
                identity,
                None,
                "testnet".to_string(),
                usize::MAX,
                counters.clone(),
                crate::config::RateLimitsConfig::default(),
            ),
            dir,
            counters,
        )
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    fn signed_channel_leave_envelope(
        sk: &ed25519_dalek::SigningKey,
        channel_id: u64,
        timestamp: u64,
    ) -> Vec<u8> {
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let payload = ChannelLeavePayload { channel_id };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ChannelLeave as u8,
            &msg_id,
            timestamp,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChannelLeave,
            msg_id,
            author,
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        rmp_serde::to_vec_named(&envelope).unwrap()
    }

    #[test]
    fn router_level_rate_limit_rejection_increments_shared_counter() {
        let (r, _dir, counters) = router();
        let sk = crypto::generate_keypair();
        let channel_id = 4242u64;
        let base = now_ms();

        // `RateCategory::ChannelMembership` (Code Audit CRITICAL #1 fix) caps
        // ChannelJoin/ChannelLeave at 20/hour — send 21 distinct-msg_id
        // ChannelLeave envelopes from the SAME wallet within the same window.
        let mut last_result = None;
        for i in 0..21u64 {
            let raw = signed_channel_leave_envelope(&sk, channel_id, base + i);
            last_result = Some(r.process_message(&raw));
        }
        assert!(
            matches!(last_result, Some(RouteResult::Rejected(ref reason)) if reason.contains("rate limited")),
            "the 21st ChannelLeave from the same wallet within the hour must be rate limited"
        );
        assert!(
            counters.snapshot().rate_limited_requests >= 1,
            "the router's own rate-limit rejection must increment the shared counter, \
             not just the HTTP-layer 429 path (Code Audit NOTE #6)"
        );
    }

    fn router_with_rate_limits(
        cfg: crate::config::RateLimitsConfig,
    ) -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        let counters = std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new());
        (
            MessageRouter::new(
                storage,
                identity,
                None,
                "testnet".to_string(),
                usize::MAX,
                counters,
                cfg,
            ),
            dir,
        )
    }

    /// Rate-limit rework (l2-node 0.122.0): a burst of `burst_max` NewsPost
    /// calls is allowed back-to-back, and the very next one is blocked.
    #[test]
    fn news_post_burst_allowed_then_blocked() {
        let cfg = crate::config::RateLimitsConfig {
            news_burst_unverified: 5,
            news_daily_unverified: 50,
            ..Default::default()
        };
        let (r, _dir) = router_with_rate_limits(cfg);
        let author = "klv1burst";
        let base = now_ms();

        for i in 0..5 {
            assert!(
                !r.is_rate_limited(author, RateCategory::NewsPost, false, base + i),
                "post {} within the burst allowance must be accepted",
                i
            );
        }
        assert!(
            r.is_rate_limited(author, RateCategory::NewsPost, false, base + 5),
            "the 6th post within the burst window must be rate limited"
        );
    }

    /// The sustained (daily) cap blocks even while the burst window still
    /// has room — the two checks are independent, not "burst OR sustained
    /// whichever is larger" (rate-limit rework §2 Change B).
    #[test]
    fn news_post_sustained_cap_blocks_despite_burst_room() {
        let cfg = crate::config::RateLimitsConfig {
            news_burst_unverified: 100, // effectively unlimited for this test
            news_daily_unverified: 3,
            ..Default::default()
        };
        let (r, _dir) = router_with_rate_limits(cfg);
        let author = "klv1sustained";
        let base = now_ms();

        for i in 0..3 {
            assert!(
                !r.is_rate_limited(author, RateCategory::NewsPost, false, base + i),
                "post {} within the daily cap must be accepted",
                i
            );
        }
        assert!(
            r.is_rate_limited(author, RateCategory::NewsPost, false, base + 3),
            "the 4th post must be rejected by the sustained cap even though \
             the burst window (100/10min) still has room"
        );
    }

    /// Once the burst window elapses, its counter resets independently of
    /// the sustained counter, which keeps accumulating across the rollover.
    #[test]
    fn news_post_burst_window_rollover_resets_only_burst_counter() {
        let cfg = crate::config::RateLimitsConfig {
            news_burst_unverified: 2,
            news_daily_unverified: 100,
            ..Default::default()
        };
        let (r, _dir) = router_with_rate_limits(cfg);
        let author = "klv1rollover";
        let base = now_ms();

        assert!(!r.is_rate_limited(author, RateCategory::NewsPost, false, base));
        assert!(!r.is_rate_limited(author, RateCategory::NewsPost, false, base + 1));
        assert!(
            r.is_rate_limited(author, RateCategory::NewsPost, false, base + 2),
            "3rd post inside the same 10-min burst window must be blocked"
        );

        // Advance past the 10-minute burst window (NEWS_BURST_WINDOW_MS).
        let after_rollover = base + NEWS_BURST_WINDOW_MS + 1;
        assert!(
            !r.is_rate_limited(author, RateCategory::NewsPost, false, after_rollover),
            "a new burst window must allow posts again after rollover"
        );
    }

    /// Change A: a registered (on-chain verified) wallet gets a materially
    /// higher NewsPost budget than an unverified one, for the same category
    /// and the same instant.
    #[test]
    fn news_post_registered_tier_gets_higher_budget() {
        let (r, _dir, _counters) = router();
        let unverified = "klv1unverified";
        let registered = "klv1registered";
        let base = now_ms();

        // Default config: unverified burst = 5, registered burst = 20.
        for i in 0..5 {
            assert!(!r.is_rate_limited(unverified, RateCategory::NewsPost, false, base + i));
        }
        assert!(
            r.is_rate_limited(unverified, RateCategory::NewsPost, false, base + 5),
            "unverified wallet must be capped at the lower burst tier"
        );

        for i in 0..20 {
            assert!(
                !r.is_rate_limited(registered, RateCategory::NewsPost, true, base + i),
                "registered post {} must be within the higher burst tier",
                i
            );
        }
        assert!(
            r.is_rate_limited(registered, RateCategory::NewsPost, true, base + 20),
            "registered wallet's 21st post must still hit its (higher) burst cap"
        );
    }

    /// `cleanup_rate_limits` must retain an entry while EITHER window is
    /// still live — evicting on the burst window alone would silently
    /// reset a sustained-window budget that's still meaningfully populated
    /// (the exact regression the rate-limit rework plan calls out as the
    /// easiest place to introduce a bug, §2 Change B). Insert the entry
    /// directly rather than driving it through `is_rate_limited`, so the
    /// burst window is unambiguously stale (2 days old, in real wall-clock
    /// terms) while the sustained window is fresh — `cleanup_rate_limits`
    /// itself reads real `SystemTime::now()`, so the test data must too.
    #[test]
    fn cleanup_retains_entry_with_live_sustained_window_after_burst_expires() {
        let (r, _dir, _counters) = router();
        let author = "klv1cleanup";
        let real_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let two_days_ago = real_now.saturating_sub(2 * 86_400_000);

        let key = format!("{}:{:?}", author, RateCategory::NewsPost);
        r.rate_limits.insert(
            key.clone(),
            RateLimitEntry {
                burst_count: 5,
                burst_window_start: two_days_ago,
                sustained_count: 40,
                sustained_window_start: real_now,
            },
        );

        r.cleanup_rate_limits();

        assert!(
            r.rate_limits.contains_key(&key),
            "cleanup must NOT evict an entry whose sustained window is still \
             live (now) just because its burst window is stale (2 days old)"
        );
    }
}
#[cfg(test)]
mod hot_topics_ingest_tests {
    //! Spec 3 §3.9 — the ingest side of Hot Topics: a `NewsPost` must index
    //! its tags in `NEWS_BY_TAG` in canonical normalized form (protocol §3.5)
    //! and feed the per-`(tag, hour)` sketch in `HOT_TOPICS_LOCAL`.
    use super::*;
    use tempfile::TempDir;

    fn router() -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        (
            MessageRouter::new(
                storage,
                identity,
                None,
                "testnet".to_string(),
                usize::MAX,
                std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()),
                crate::config::RateLimitsConfig::default(),
            )
            .with_hot_topics_config(crate::config::HotTopicsConfig::default()),
            dir,
        )
    }

    fn news_envelope(author: &str, msg_id: [u8; 32], ts: u64, tags: &[&str]) -> Envelope {
        let payload = NewsPostPayload {
            title: "t".into(),
            content: "c".into(),
            content_rating: Default::default(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            attachments: vec![],
            visibility: Default::default(),
        };
        Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::NewsPost,
            msg_id,
            author: author.to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        }
    }

    #[test]
    fn news_post_indexes_normalized_tags_and_feeds_the_sketch() {
        let (r, _d) = router();
        let ts = crate::util::now_ms();
        let msg_id = [7u8; 32];
        // Mixed-case, hashed, and one un-normalizable tag.
        let env = news_envelope("klv1a", msg_id, ts, &["#Klever", "DeFi", "bad tag"]);
        r.storage
            .put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&env).unwrap())
            .unwrap();
        r.update_indexes(&env, "klv1a").unwrap();

        // NEWS_BY_TAG holds the canonical form only.
        assert!(r
            .storage
            .prefix_iter_cf(schema::cf::NEWS_BY_TAG, &schema::news_by_tag_prefix("klever"), 4)
            .unwrap()
            .len()
            == 1);
        assert!(r
            .storage
            .prefix_iter_cf(schema::cf::NEWS_BY_TAG, &schema::news_by_tag_prefix("defi"), 4)
            .unwrap()
            .len()
            == 1);
        // The raw "Klever" / "bad tag" never entered the index.
        assert!(r
            .storage
            .prefix_iter_cf(schema::cf::NEWS_BY_TAG, &schema::news_by_tag_prefix("Klever"), 4)
            .unwrap()
            .is_empty());

        // HOT_TOPICS_LOCAL has a sketch for (bucket, klever) estimating 1.
        let bucket = ts / schema::HOT_TOPICS_BUCKET_MS;
        let raw = r
            .storage
            .get_cf(schema::cf::HOT_TOPICS_LOCAL, &schema::encode_hot_topics_key(bucket, "klever"))
            .unwrap()
            .expect("sketch present");
        let hll = crate::hll::Hll::from_bytes(&raw).expect("decodes");
        assert_eq!(hll.estimate_u32(), 1);
    }

    #[test]
    fn max_tracked_tags_per_bucket_drops_new_tags_once_full() {
        let (mut r, _d) = router();
        r.hot_topics_config.max_tracked_tags_per_bucket = 2;
        let ts = crate::util::now_ms();
        let bucket = ts / schema::HOT_TOPICS_BUCKET_MS;
        for (i, tag) in ["a", "b", "c"].iter().enumerate() {
            let msg_id = [i as u8; 32];
            let env = news_envelope("klv1a", msg_id, ts, &[tag]);
            r.storage
                .put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&env).unwrap())
                .unwrap();
            r.update_indexes(&env, "klv1a").unwrap();
        }
        let tracked = r
            .storage
            .count_prefix_cf(schema::cf::HOT_TOPICS_LOCAL, &bucket.to_be_bytes(), 10)
            .unwrap();
        assert_eq!(tracked, 2, "third distinct tag must be dropped at the cap");
    }
}
