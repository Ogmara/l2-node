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
use crate::storage::rocks::{MembershipEvent, Storage};
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

/// Outcome of a SUCCESSFUL `MessageRouter::verify_private_join` (private-
/// channel join gate, l2-node 0.140.0). Every variant means "accept";
/// a rejection is the `Err` side. Kept as distinct variants (rather than a
/// bool) so tests can assert WHICH rule admitted a join — a verdict that
/// silently skipped verification is the failure shape this guards against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JoinVerdict {
    /// Rule 1: not a private channel — no proof needed (any attached
    /// `invite` is ignored; it was already size-capped by validation).
    NotPrivate,
    /// Rule 2: the joiner is already a member, or is the creator.
    AlreadyMemberOrCreator,
    /// Rule 3: proofless join signed before
    /// `private_join_proof_activation_ms`.
    LegacyBeforeActivation,
    /// Rules 4-8: a valid invite from the creator or a verified moderator.
    Invited,
    /// Rules 4-7 passed but the channel is unknown locally, so the
    /// inviter's authority (rule 8) cannot be checked yet. Accepted and
    /// stored; membership is NOT applied (there is no channel row) —
    /// identical to the pre-gate unknown-channel behaviour.
    InvitedUnknownChannel,
}

/// Which rule-8 branch authorized an invite's inviter. Carried out of the
/// (crypto-heavy) verification so the apply step can re-check it under the
/// membership lock with cheap reads only (security audit N2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InviterAuthority {
    /// The inviter is the channel creator.
    Creator,
    /// A valid creator-signed grant dated `grant_ts`.
    Grant { grant_ts: u64 },
    /// The inviter is listed in local `CHANNEL_MODERATORS`.
    LocalModerator,
}

/// Facts about the invite a join was admitted with.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InviteFacts {
    inviter: String,
    invite_ts: u64,
    /// `None` for an unknown channel (rule 8 not evaluated).
    authority: Option<InviterAuthority>,
    /// See `verify_inviter_authority`.
    kill_horizon: u64,
}

/// A successful `verify_private_join`: the verdict plus what the apply
/// step needs to re-check under the membership lock without repeating any
/// signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedJoin {
    pub(crate) verdict: JoinVerdict,
    invite: Option<InviteFacts>,
}

/// Why `MessageRouter::federate_bootstrap_gate` refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BootstrapGateError {
    /// The host's `ChannelCreate` is not a valid, correctly-derived private
    /// channel creation for this id (the host's fault — maps to 502).
    BadBootstrap(String),
    /// The caller is not entitled to join (maps to 403).
    Denied(String),
}

/// What the join gate knows about a channel id locally.
enum ChannelGateInfo {
    /// A `CHANNELS` row exists.
    Known { private: bool, creator: Option<String> },
    /// No local row. `private` is inferred from the id namespace
    /// (`channel_id > PRIVATE_CHANNEL_ID_FLOOR`).
    Unknown { private: bool },
}

/// A `ChannelInvite` envelope that passed the join gate's structural,
/// binding, time and removal-cutoff checks (rules 4-7).
struct VerifiedInvite {
    /// Wallet the invite's signing key resolves to.
    inviter: String,
    /// The invite envelope's signed timestamp.
    invite_ts: u64,
    /// The invite's raw `inviter_grant`, if any.
    inviter_grant: Option<Vec<u8>>,
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
    ChannelCreate,     // 20 per hour (audit 2026-09-29 — see limits() doc comment)
    ProfileUpdate,     // 20/hour unverified, 60/hour registered (spec 01 §6.1)
    KeyEnvelope,       // 240 per minute (0x61, l2-node 0.143.0)
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
            // Split out of `Other` (100/min) in 0.127.0. A ProfileUpdate can now
            // carry a bot descriptor, whose arrival broadcasts
            // `bot_commands_changed` to every connected client — and bots
            // republish their descriptor on EVERY start (spec 01 §3.11), so a
            // crash-looping bot at 100/min would flood the profile topic and fan
            // that out network-wide. Deliberately NO bot exemption: a descriptor
            // is metadata, not service, and no legitimate bot rewrites its
            // command list more than a few times an hour. A bot needing a higher
            // MESSAGE allowance gets it from the registered tier on ChatMessages,
            // not from here.
            Self::ProfileUpdate => {
                RateLimits::flat(if registered { 60 } else { 20 }, 3_600_000)
            }
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
            // Audit 2026-09-29: ChannelCreate previously had NO dedicated
            // category at all and fell into `Other`'s 100/min — 144,000/day
            // per wallet. Each accepted ChannelCreate for a not-yet-locally-
            // known channel_id mints a permanent CHANNELS row and a
            // permanent obligation for `sweep_channel_verification` to keep
            // re-checking it (a channel the SC has never heard of never
            // becomes "verified" and so is never excluded from future
            // sweeps). A single wallet at the old limit could inject far
            // more junk unverified rows per day than any realistic
            // legitimate channel-creation rate, competing for the same
            // sweep budget as real channels. 20/hour (480/day) is generous
            // for legitimate use (channel creation is an infrequent,
            // deliberate action) while cutting the injection ceiling
            // ~300x.
            Self::ChannelCreate => RateLimits::flat(20, 3_600_000),
            // l2-node 0.143.0: `ChannelKeyEnvelope` (0x61) split out of
            // `Other` (100/min, shared with everything uncategorised). One
            // epoch establishment wraps the key to every member device, so a
            // 100-member channel legitimately needs a few hundred envelopes in
            // a burst; 240/min is that burst while still bounding the
            // per-wallet write rate into the capped `channel_keys` scope. The
            // API answers THIS category with 429 + `retry_after_ms` so the SDK
            // can pace instead of failing (other categories stay 400).
            Self::KeyEnvelope => RateLimits::flat(240, 60_000),
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
            MessageType::ProfileUpdate => Self::ProfileUpdate,
            MessageType::KeyVaultSync => Self::KeyVault,
            MessageType::DeviceEncBinding | MessageType::DeviceEncRevoke => Self::DeviceEnc,
            MessageType::ChannelJoin | MessageType::ChannelLeave => Self::ChannelMembership,
            MessageType::ChannelCreate => Self::ChannelCreate,
            MessageType::ChannelKeyEnvelope => Self::KeyEnvelope,
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


/// Where an envelope entered this node — selects which per-node budgets
/// apply (see `process_gossip_message`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ingress {
    /// This node's own clients (REST / WebSocket / local subsystems).
    Local,
    /// Relayed by a peer over gossipsub (live semantics).
    Gossip,
    /// Sync / backfill (no drift check, no rate limits).
    Sync,
}

/// Node wall clock (ms since the Unix epoch).
fn wall_clock_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

/// What happened to a key envelope that reached arbitration without being
/// stored (see `UnstoredKeyCache`).
#[derive(Debug, Clone)]
enum UnstoredOutcome {
    /// Its slot already held a wrap.
    AlreadyPresent,
    /// It lost arbitration.
    Conflict(Box<KeyConflictInfo>),
    /// Step 7h refused it (a `key_envelope_rejected:` reason).
    Rejected(String),
}

/// Max entries of the unstored-key-envelope seen-cache. Worst case (every
/// entry a conflict with a 62-char author), per entry: a HashMap slot of
/// about 74 B (32-byte key, 8-byte timestamp, 24-byte outcome, at 0.875
/// load), a VecDeque slot of 40 B, the boxed `KeyConflictInfo` (~150 B)
/// and the author string (62 B) — about 330 B, i.e. ~33 MB at 100,000
/// entries; ~12 MB if all are already-present. Pinned by
/// `unstored_cache_entry_sizes`.
const UNSTORED_KEY_CACHE_MAX: usize = 100_000;
/// Seen-cache TTL: 10 min, twice the ±5 min drift window, so a live replay
/// of a cached envelope is always answered from the cache.
const UNSTORED_KEY_CACHE_TTL_MS: u64 = 600_000;

/// Bounded, oldest-first seen-cache of unstored key envelopes (round-5
/// audit B1). FIFO insertion order doubles as age order, so expiry and
/// overflow both pop from the front.
#[derive(Default)]
struct UnstoredKeyCache {
    map: std::collections::HashMap<[u8; 32], (u64, UnstoredOutcome)>,
    order: std::collections::VecDeque<([u8; 32], u64)>,
}

impl UnstoredKeyCache {
    fn expire(&mut self, now_ms: u64) {
        while let Some((id, at)) = self.order.front().copied() {
            if now_ms.saturating_sub(at) <= UNSTORED_KEY_CACHE_TTL_MS && self.order.len() <= UNSTORED_KEY_CACHE_MAX {
                break;
            }
            self.order.pop_front();
            // Only drop the map entry if it is this very insertion.
            if self.map.get(&id).is_some_and(|(t, _)| *t == at) {
                self.map.remove(&id);
            }
        }
    }

    fn lookup(&mut self, id: &[u8; 32], now_ms: u64) -> Option<UnstoredOutcome> {
        self.expire(now_ms);
        self.map.get(id).map(|(_, o)| o.clone())
    }

    fn insert(&mut self, id: [u8; 32], outcome: UnstoredOutcome, now_ms: u64) {
        if self.map.contains_key(&id) {
            return;
        }
        self.map.insert(id, (now_ms, outcome));
        self.order.push_back((id, now_ms));
        self.expire(now_ms);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

/// A token bucket (gossip-ingress key-envelope limits).
#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: f64,
    last_ms: u64,
}

/// Capacity and refill rate of a [`TokenBucket`].
#[derive(Debug, Clone, Copy)]
struct BucketSpec {
    capacity: f64,
    refill_per_ms: f64,
}

impl BucketSpec {
    /// Token level of `b` at `now_ms` (refilled, capped).
    fn level(self, b: TokenBucket, now_ms: u64) -> f64 {
        let elapsed = now_ms.saturating_sub(b.last_ms) as f64;
        (b.tokens + elapsed * self.refill_per_ms).min(self.capacity)
    }
}

/// Gossip key envelopes per wallet: capacity 720, +4/s.
const GOSSIP_KEY_WALLET_BUCKET: BucketSpec = BucketSpec { capacity: 720.0, refill_per_ms: 4.0 / 1000.0 };
/// Gossip key envelopes per (wallet, channel scope): capacity 180, +1/s.
const GOSSIP_KEY_SCOPE_BUCKET: BucketSpec = BucketSpec { capacity: 180.0, refill_per_ms: 1.0 / 1000.0 };
/// Max tracked gossip key-envelope buckets (≈ 100k active wallets).
const GOSSIP_KEY_BUCKETS_MAX: usize = 200_000;
/// Rejection reason for a gossip key envelope over its token bucket (maps to
/// gossipsub `Ignore`; never reaches an HTTP client).
pub(crate) const GOSSIP_KEY_RATE_LIMITED_REASON: &str = "rate limited (KeyEnvelope gossip bucket)";

/// The channel scope of a channel-scope `ChannelKeyEnvelope`, else `None`.
fn channel_key_scope(envelope: &Envelope) -> Option<[u8; 32]> {
    rmp_serde::from_slice::<ChannelKeyEnvelopePayload>(&envelope.payload)
        .ok()
        .filter(|p| p.scope_kind == crate::messages::types::key_scope_kind::CHANNEL)
        .map(|p| p.key_scope)
}

/// Per-(wallet, channel scope) budget for `ChannelKeyEnvelope`s (l2-node
/// 0.143.0, round-2 audit W-D) — see `arbitrate_channel_key`.
const KEY_ENVELOPE_SCOPE_LIMITS: RateLimits = RateLimits::flat(60, 60_000);

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
    /// Local-ingress per-(wallet, channel scope) key-envelope windows
    /// (60/min), separate from `rate_limits` so they can be pruned on their
    /// own 60 s schedule.
    local_key_scope_windows: DashMap<String, RateLimitEntry>,
    /// Gossip-ingress key-envelope token buckets (per wallet, and per
    /// wallet:scope), bounded by `GOSSIP_KEY_BUCKETS_MAX`.
    gossip_key_buckets: DashMap<String, TokenBucket>,
    /// Last prune of the two maps above (node clock ms).
    key_bucket_last_prune_ms: std::sync::atomic::AtomicU64,
    /// Last FORCED prune of `gossip_key_buckets` at its size cap.
    gossip_forced_prune_ms: std::sync::atomic::AtomicU64,
    /// Seen-cache of key envelopes that reached arbitration but were not
    /// stored (Step 3b). In memory only: a restart forgets it (replays are
    /// then evaluated, and rate-limited, normally again).
    unstored_key_envelopes: std::sync::Mutex<UnstoredKeyCache>,
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
    /// Channel-identity-verification policy (security fix, 2026-10-06) —
    /// currently just `require_private_id_derivation`, see that field's
    /// doc comment. Defaults to `ChannelVerifyConfig::default()` (`true`);
    /// production overrides via `with_channel_verify_config`.
    channel_verify_config: crate::config::ChannelVerifyConfig,
}

/// Reason of EVERY router rejection caused by a local infrastructure
/// failure (storage, identity resolution) — a fixed string. The underlying
/// error (RocksDB / anyhow text) is logged by `internal_error`, never put
/// in the reason, because reasons reach HTTP clients;
/// `api::routes::rejection_response` maps exactly this reason to a generic
/// 500 (round-4 audit 9b). Step-7 wrappers pass it through unprefixed
/// (`wrap_rejection`).
pub(crate) const INTERNAL_ERROR_REASON: &str = "storage error";

/// Log an internal failure with its detail and return the fixed
/// `INTERNAL_ERROR_REASON` (see there).
fn internal_error(context: &str, e: impl std::fmt::Display) -> String {
    warn!(context, error = %e, "router: internal error (not echoed to the client)");
    INTERNAL_ERROR_REASON.to_string()
}

/// Prefix a step-7 rejection reason with its step label — except the
/// internal-error reason, which stays exact so the API can classify it.
fn wrap_rejection(prefix: &str, e: String) -> String {
    if e == INTERNAL_ERROR_REASON {
        e
    } else {
        format!("{prefix}: {e}")
    }
}

/// Rejection reason for step 4d (tiered identity). Shared with
/// `network::handle_gossip_message`, which pattern-matches on this exact
/// text to decide whether a `Rejected` result is a routine policy denial
/// (debug!) or a chain-scan-lag signal worth surfacing at warn! — keep both
/// sites on this constant so the two never drift apart.
pub const REGISTRATION_REQUIRED_REASON: &str =
    "on-chain registration required: verify your wallet to use this feature";

/// Prefix of every Step-7h (key-epoch arbitration) rejection reason:
/// `"key_envelope_rejected:<code>: <detail>"`. The API answers these with a
/// 400 JSON body `{"error": "<code>", "message": "<detail>"}` (see
/// [`parse_key_envelope_rejection`]); codes are stable for SDK matching.
pub const KEY_ENVELOPE_REJECT_PREFIX: &str = "key_envelope_rejected:";

/// Build a Step-7h rejection reason (see [`KEY_ENVELOPE_REJECT_PREFIX`]).
pub fn key_envelope_rejection(code: &str, detail: &str) -> String {
    format!("{KEY_ENVELOPE_REJECT_PREFIX}{code}: {detail}")
}

/// Split a Step-7h rejection reason into `(code, detail)`; `None` for any
/// other reason.
pub fn parse_key_envelope_rejection(reason: &str) -> Option<(&str, &str)> {
    let rest = reason.strip_prefix(KEY_ENVELOPE_REJECT_PREFIX)?;
    Some(match rest.split_once(": ") {
        Some((c, d)) => (c, d),
        None => (rest, ""),
    })
}

/// Prefix of the Step-6 rejection reason for the `KeyEnvelope` rate
/// category; the decimal `retry_after_ms` follows. The API turns exactly
/// this into `429 {"error":"rate_limited","retry_after_ms":N}` (every other
/// category keeps the plain 400 "rate limited (…)").
pub const KEY_ENVELOPE_RATE_LIMITED_PREFIX: &str = "rate limited (KeyEnvelope); retry_after_ms=";

/// `retry_after_ms` of a `KeyEnvelope` rate-limit rejection, else `None`.
pub fn parse_key_envelope_retry_after(reason: &str) -> Option<u64> {
    reason.strip_prefix(KEY_ENVELOPE_RATE_LIMITED_PREFIX)?.parse().ok()
}

/// What happened to the wrap of an accepted channel-scope
/// `ChannelKeyEnvelope` (POST `key_status`, l2-node 0.143.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// The wrap was stored for its `(target, device, epoch)`.
    Stored,
    /// A wrap of the same winning key already existed for that slot (kept).
    AlreadyPresent,
}

impl KeyStatus {
    /// Wire string (`"stored"` / `"already_present"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::AlreadyPresent => "already_present",
        }
    }
}

/// A channel-scope `ChannelKeyEnvelope` lost key-epoch arbitration
/// (l2-node 0.143.0): a different commitment is recorded for its
/// `(scope, epoch)` and this one either ranks worse or arrived after the
/// finality horizon. Carried by [`RouteResult::KeyConflict`].
#[derive(Debug, Clone)]
pub struct KeyConflictInfo {
    /// Channel of the conflicting envelope.
    pub channel_id: u64,
    /// Epoch of the conflicting envelope.
    pub epoch: u64,
    /// Arbitration state of the epoch (always `"arbitrated"` today).
    pub state: &'static str,
    /// The recorded winner.
    pub winner: crate::storage::key_commits::KeyCommitWinner,
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
        /// Resolved wallet address that authored this envelope — always
        /// populated (unlike `bot_commands_changed` below), including on the
        /// sync path. Lets callers (the broadened identity-sync trigger in
        /// `network/mod.rs::handle_gossip_message`) act on "who sent this"
        /// without re-parsing `raw_bytes` and re-resolving device→wallet
        /// themselves.
        author: String,
        /// `Some(wallet)` when this envelope actually changed that wallet's bot
        /// descriptor, so the caller should emit `bot_commands_changed` and drop
        /// the affected discovery-cache entries (spec 3 §4.3).
        ///
        /// Carried out of the router rather than recomputed downstream because
        /// the comparison needs the PRE-merge record, which no longer exists by
        /// the time notifications run. Always `None` from
        /// `process_synced_message` — enforced by an explicit `!is_sync` gate at
        /// the construction site, NOT merely by sync's callers ignoring it —
        /// which is how identity-sync, a path that bypasses rate limiting by
        /// design, is prevented from triggering a broadcast storm during
        /// backfill that no rate limit could bound.
        bot_commands_changed: Option<String>,
        /// `Some` only for a channel-scope `ChannelKeyEnvelope`: whether its
        /// wrap was stored or the slot already held the winning key
        /// (POST `key_status`, l2-node 0.143.0).
        key_status: Option<KeyStatus>,
    },
    /// Message is a duplicate (already stored).
    Duplicate,
    /// A channel-scope `ChannelKeyEnvelope` lost key-epoch arbitration
    /// (l2-node 0.143.0). Policy, not invalidity: over gossip this maps to
    /// `Ignore` (a losing-but-honest concurrent establisher's wraps are
    /// still relayed by peers that saw them first); the API answers 409
    /// with a JSON body naming the winner; sync/backfill treat it like
    /// `Rejected`. Nothing was stored.
    KeyConflict(Box<KeyConflictInfo>),
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
            local_key_scope_windows: DashMap::new(),
            gossip_key_buckets: DashMap::new(),
            key_bucket_last_prune_ms: std::sync::atomic::AtomicU64::new(0),
            gossip_forced_prune_ms: std::sync::atomic::AtomicU64::new(0),
            unstored_key_envelopes: std::sync::Mutex::new(UnstoredKeyCache::default()),
            rate_limits_config,
            registration_cache: DashMap::new(),
            pow,
            network,
            dm_recipient_cap,
            dm_recipient_cap_lock: std::sync::Mutex::new(()),
            counters,
            hot_topics_config: crate::config::HotTopicsConfig::default(),
            channel_verify_config: crate::config::ChannelVerifyConfig::default(),
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

    /// Override the channel-identity-verification policy (production
    /// wiring — tests keep the default, which is `require_private_id_
    /// derivation: true`). Builder-style, mirroring `with_hot_topics_config`.
    pub fn with_channel_verify_config(
        mut self,
        cfg: crate::config::ChannelVerifyConfig,
    ) -> Self {
        self.channel_verify_config = cfg;
        self
    }

    /// Test access to the router's storage handle.
    #[cfg(test)]
    pub(crate) fn storage(&self) -> &Storage {
        &self.storage
    }

    /// Test access to the router's identity resolver.
    #[cfg(test)]
    pub(crate) fn identity(&self) -> &IdentityResolver {
        &self.identity
    }

    /// Process a raw message through the full pipeline.
    ///
    /// Returns the routing result indicating whether the message was
    /// accepted, is a duplicate, or was rejected.
    pub fn process_message(&self, raw_bytes: &[u8]) -> RouteResult {
        self.process_message_inner(raw_bytes, Ingress::Local, None)
    }

    /// Process a message received over GOSSIP. Identical to
    /// [`Self::process_message`] (live semantics: drift check, signature,
    /// arbitration, size limits, per-wallet rate limits for every other
    /// type) except that `ChannelKeyEnvelope`s are exempt from ALL
    /// per-wallet budgets (240/min and the per-(wallet, scope) 60/min).
    /// Those are per-node fixed windows: a cover burst the home node
    /// accepted could be refused by a peer, and key envelopes are never
    /// backfilled, so the wrap would be lost for good (round-3 audit W2 and
    /// the sdk-js audit). They are enforced where the client is: at the
    /// home node's API / WebSocket ingress.
    pub fn process_gossip_message(&self, raw_bytes: &[u8]) -> RouteResult {
        self.process_message_inner(raw_bytes, Ingress::Gossip, None)
    }

    /// Process a synced historical message — skips timestamp drift and rate limiting.
    ///
    /// Used for messages received via the sync protocol, which are intentionally
    /// older than the 5-minute drift window. All other validation (signature,
    /// identity, payload, dedup) still applies.
    pub fn process_synced_message(&self, raw_bytes: &[u8]) -> RouteResult {
        self.process_message_inner(raw_bytes, Ingress::Sync, None)
    }

    /// Test-only: the LIVE pipeline evaluated at a fixed node clock, so
    /// deterministic fixtures with fixed timestamps can exercise live-only
    /// rules (drift window, establishing a key epoch) without wall-clock time.
    #[cfg(test)]
    pub(crate) fn process_message_at(&self, raw_bytes: &[u8], now_ms: u64) -> RouteResult {
        self.process_message_inner(raw_bytes, Ingress::Local, Some(now_ms))
    }

    /// Test-only: the GOSSIP pipeline at a fixed node clock.
    #[cfg(test)]
    pub(crate) fn process_gossip_message_at(&self, raw_bytes: &[u8], now_ms: u64) -> RouteResult {
        self.process_message_inner(raw_bytes, Ingress::Gossip, Some(now_ms))
    }

    fn process_message_inner(&self, raw_bytes: &[u8], ingress: Ingress, now_override: Option<u64>) -> RouteResult {
        let is_sync = ingress == Ingress::Sync;
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
            Err(e) => return RouteResult::Rejected(internal_error("storage", e)),
        }
        // Step 3b (round-5 audit B1): key envelopes that reached arbitration
        // but were NOT stored, with an outcome that can never change (see
        // the caching rules at Step 7h), are remembered by msg_id for 10 min.
        // A replay is answered here — BEFORE any rate window / token bucket
        // is touched — so a third party re-submitting someone else's
        // envelope can no longer burn that wallet's budget. Already-present
        // → `Duplicate` (it IS effectively stored); conflict / refusal → the
        // same answer as the first time (a `Duplicate` would read as success
        // to a client). Like Step 3 this precedes the signature check: a
        // forged envelope reusing a cached msg_id just gets the cached
        // answer — never a trust signal. A cached conflict reports the
        // winner as of its first evaluation, which may be outdated (the
        // winner can only have improved since).
        if envelope.msg_type == MessageType::ChannelKeyEnvelope {
            let cached = self
                .unstored_key_envelopes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .lookup(&envelope.msg_id, now_override.unwrap_or_else(wall_clock_ms));
            if let Some(outcome) = cached {
                return match outcome {
                    UnstoredOutcome::AlreadyPresent => RouteResult::Duplicate,
                    UnstoredOutcome::Conflict(info) => RouteResult::KeyConflict(info),
                    UnstoredOutcome::Rejected(reason) => RouteResult::Rejected(reason),
                };
            }
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
            Err(e) => return RouteResult::Rejected(internal_error("identity resolution", e)),
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

        let now_ms = now_override.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        });

        // Step 5: Verify timestamp (±5 min drift) — skipped for synced historical messages
        if !is_sync && !envelope.is_timestamp_valid(now_ms) {
            return RouteResult::Rejected(format!(
                "timestamp drift too large: {} vs now {}",
                envelope.timestamp, now_ms
            ));
        }

        // Step 6 for key envelopes: local ingress only, two buckets, refused
        // attempts consume nothing (see `key_envelope_rate_limit`).
        if envelope.msg_type == MessageType::ChannelKeyEnvelope {
            match ingress {
                Ingress::Local => {
                    let registered = self.is_registered_cached(&resolved_author, now_ms);
                    if let Some(retry_after_ms) =
                        self.key_envelope_rate_limit(&envelope, &resolved_author, registered, now_ms)
                    {
                        self.counters.inc_rate_limited();
                        return RouteResult::Rejected(format!("{KEY_ENVELOPE_RATE_LIMITED_PREFIX}{retry_after_ms}"));
                    }
                }
                // Gossip: token buckets, checked AFTER authorization (just
                // before Step 7h) so only members' envelopes ever create
                // bucket entries — the gossip router has no PoW gate, and
                // fresh keypairs must not be able to fill the bounded map.
                // Sync: no rate limits; Step 7h accepts only wraps of the
                // already recorded winner on that path (and no current sync
                // protocol carries key envelopes at all).
                Ingress::Gossip | Ingress::Sync => {}
            }
        }
        // Step 6: Rate limit by wallet address — skipped for synced messages
        else if !is_sync && envelope.msg_type.requires_registration() {
            let category = RateCategory::from_msg_type(envelope.msg_type);
            let registered = self.is_registered_cached(&resolved_author, now_ms);
            if self
                .rate_limit_check(&resolved_author, category, registered, now_ms)
                .is_some()
            {
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
        if let Err(e) = self.validate_payload(&envelope, &resolved_author, is_sync) {
            return RouteResult::Rejected(format!("payload validation failed: {}", e));
        }

        // Step 7b: Check ban enforcement — banned users cannot post to channels
        if let Err(e) = self.check_channel_ban(&envelope, &resolved_author) {
            return RouteResult::Rejected(wrap_rejection("banned", e));
        }

        // Step 7b2: Check mute enforcement — muted users cannot send messages/reactions
        if let Err(e) = self.check_channel_mute(&envelope, &resolved_author) {
            return RouteResult::Rejected(wrap_rejection("muted", e));
        }

        // Step 7c: Authorize channel admin operations
        if let Err(e) = self.authorize_channel_action(&envelope, &resolved_author, is_sync) {
            return RouteResult::Rejected(wrap_rejection("unauthorized", e));
        }

        // Step 7d: Authorize edit/delete operations — author must match original, edits have 30-min window
        if let Err(e) = self.authorize_edit_delete(&envelope, &resolved_author, now_ms) {
            return RouteResult::Rejected(wrap_rejection("edit/delete denied", e));
        }

        // Step 7d2: Authorize DM reactions — reactor must be a participant of
        // the target DM conversation (audit W27 security follow-up).
        if let Err(e) = self.authorize_dm_reaction(&envelope, &resolved_author) {
            return RouteResult::Rejected(wrap_rejection("dm_reaction_denied", e));
        }

        // Step 7d3: Authorize DeletionRequest — a SingleMessage deletion may
        // only target the sender's own message (security audit, BLOCKING).
        if let Err(e) = self.authorize_deletion_request(&envelope, &resolved_author) {
            return RouteResult::Rejected(wrap_rejection("deletion_denied", e));
        }

        // Step 7e: Read-only / broadcast channel enforcement — only creator and
        // moderators can post ChatMessage / ChatEdit / ChatDelete in ReadPublic
        // channels. Reactions remain open to all members. See protocol spec §3.6.
        if let Err(e) = self.check_readonly_channel(&envelope, &resolved_author) {
            return RouteResult::Rejected(wrap_rejection("broadcast_channel_post_denied", e));
        }

        // Step 7f (P4): an `encryption_enabled` channel rejects plaintext-text chat
        // (no-downgrade guarantee). Encrypted + attachment-only messages pass.
        if let Err(e) = self.check_channel_encryption_required(&envelope) {
            return RouteResult::Rejected(wrap_rejection("channel_encryption_required", e));
        }

        // Step 7g (audit final pre-mainnet W11): per-recipient DM storage cap.
        // Atomically checks AND reserves (increments) the slot — see
        // `reserve_dm_recipient_slot` doc for why check-then-later-increment
        // was a TOCTOU race under concurrent requests. Rejects rather than
        // evicts. Must run BEFORE Step 8's unconditional store, or a
        // rejected message would still consume disk as an orphaned,
        // unindexed MESSAGES row.
        if let Err(e) = self.reserve_dm_recipient_slot(&envelope) {
            return RouteResult::Rejected(wrap_rejection("dm_recipient_cap_exceeded", e));
        }

        // Step 7h (l2-node 0.143.0): key-epoch arbitration for channel-scope
        // `ChannelKeyEnvelope`s. Decides the envelope against the recorded
        // winner of its `(scope, epoch)` and — when accepted — stores the
        // commit row, any superseded-loser deletions, the wrap AND the raw
        // envelope in ONE batch, so Step 8 below is skipped for it. DM-scope
        // envelopes return `None` and take the generic path unchanged.
        let mut key_status: Option<KeyStatus> = None;
        if envelope.msg_type == MessageType::ChannelKeyEnvelope
            && ingress == Ingress::Gossip
            && !self.gossip_key_envelope_allowed(&envelope, &resolved_author, now_ms)
        {
            self.counters.inc_rate_limited();
            return RouteResult::Rejected(GOSSIP_KEY_RATE_LIMITED_REASON.into());
        }
        if envelope.msg_type == MessageType::ChannelKeyEnvelope {
            let res = self.arbitrate_channel_key(&envelope, &resolved_author, raw_bytes, now_ms, ingress);
            // Remember unstored outcomes (Step 3b) — ONLY outcomes that can
            // never change for this exact envelope, and never ones produced
            // on the sync path (path-dependent: e.g. `key_sync_not_winner`
            // must not shadow a later live delivery of the same bytes):
            //  * already present — the slot is write-once (only eviction or a supersede can
            //    free it; a 10 min `Duplicate` then is harmless);
            //  * conflict — a worse pair stays worse (the winner only
            //    improves) and a final epoch stays final;
            //  * below floor / evicted — floor and horizon only rise;
            //  * commitment invalid — content-only.
            // NOT cached: `key_ts_stale` (the same pair may become the winner
            // when its fresher establishing envelope arrives later, after
            // which this cover is acceptable), `key_scope_full` (space can be
            // freed), `key_epoch_too_far` (the known maximum grows),
            // `key_commitment_required`, rate limits, authorization failures
            // and internal errors.
            let remember = if ingress == Ingress::Sync {
                None
            } else {
                match &res {
                    Ok(Some(KeyStatus::AlreadyPresent)) => Some(UnstoredOutcome::AlreadyPresent),
                    Err(RouteResult::KeyConflict(info)) => Some(UnstoredOutcome::Conflict(info.clone())),
                    Err(RouteResult::Rejected(r))
                        if parse_key_envelope_rejection(r).is_some_and(|(code, _)| {
                            matches!(code, "key_epoch_below_floor" | "key_epoch_evicted" | "key_commitment_invalid")
                        }) =>
                    {
                        Some(UnstoredOutcome::Rejected(r.clone()))
                    }
                    _ => None,
                }
            };
            if let Some(o) = remember {
                self.unstored_key_envelopes
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(envelope.msg_id, o, now_ms);
            }
            match res {
                Ok(None) => {}
                Ok(Some(status)) => key_status = Some(status),
                Err(result) => return result,
            }
        }

        // Step 8: Store message (atomically increments total_messages counter)
        if key_status.is_some() {
            // Already persisted by Step 7h's batch.
        } else if let Err(e) = self.storage.store_message(&envelope.msg_id, raw_bytes) {
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
            return RouteResult::Rejected(internal_error("storage", e));
        }

        // Step 8b: Update indexes using resolved wallet address
        let bot_changed = match self.update_indexes_with(&envelope, &resolved_author, is_sync) {
            Ok(changed) => changed,
            Err(e) => {
                warn!(error = %e, "Failed to update indexes (message still stored)");
                false
            }
        };

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
            author: resolved_author.clone(),
            // `&& !is_sync` is load-bearing, not belt-and-braces. Identity-sync
            // calls this same function via `process_synced_message`, so without
            // the gate a backfill of N ProfileUpdates would emit N broadcasts —
            // and the sync path deliberately bypasses rate limiting, so the
            // ProfileUpdate category could not bound them. The sync call sites
            // happen to discard the result today, which makes this invariant
            // true by accident; the gate makes it true by construction.
            bot_commands_changed: if bot_changed && !is_sync {
                Some(resolved_author.clone())
            } else {
                None
            },
            key_status,
        }
    }

    /// Step 7h body (l2-node 0.143.0) — see `storage::key_commits` for the
    /// arbitration rules. `Ok(None)`: not a channel-scope envelope, continue
    /// with the generic Step 8. `Ok(Some(_))`: accepted and fully persisted.
    /// `Err(result)`: rejected / conflict, nothing written.
    fn arbitrate_channel_key(
        &self,
        envelope: &Envelope,
        resolved_author: &str,
        raw_bytes: &[u8],
        now_ms: u64,
        ingress: Ingress,
    ) -> Result<Option<KeyStatus>, RouteResult> {
        let is_sync = ingress == Ingress::Sync;
        // (Key-envelope rate limits live in Step 6 —
        // `key_envelope_rate_limit` — so a refused attempt never consumes.)
        use crate::storage::key_commits::{ChannelKeyArbInput, ChannelKeyArbOutcome};
        let p = rmp_serde::from_slice::<ChannelKeyEnvelopePayload>(&envelope.payload)
            .map_err(|e| RouteResult::Rejected(format!("invalid channel key envelope: {e}")))?;
        if p.scope_kind != crate::messages::types::key_scope_kind::CHANNEL {
            return Ok(None);
        }
        let reject = |code: &str, detail: &str| RouteResult::Rejected(key_envelope_rejection(code, detail));
        // Structural commitment rules (channel scope only).
        if p.key_commitment.is_some() != p.key_ts.is_some() {
            return Err(reject(
                "key_commitment_invalid",
                "key_commitment and key_ts must be present together",
            ));
        }
        if let Some(c) = p.key_commitment {
            if c.iter().all(|&b| b == 0) {
                return Err(reject("key_commitment_invalid", "key_commitment must not be all-zero"));
            }
        }
        if let Some(kts) = p.key_ts {
            if kts == 0 || kts > envelope.timestamp {
                return Err(reject(
                    "key_commitment_invalid",
                    "key_ts must be > 0 and <= the envelope timestamp",
                ));
            }
        }
        let channel_id = p
            .channel_id
            .ok_or_else(|| RouteResult::Rejected("channel key envelope missing channel_id".into()))?;

        let mut rec = serde_json::json!({
            "eph_pub": hex::encode(p.eph_pub),
            "nonce": hex::encode(p.nonce),
            "wrapped": hex::encode(&p.wrapped),
            "epoch": p.epoch,
            "scope_kind": p.scope_kind,
            "author": resolved_author,
            "timestamp": envelope.timestamp,
            "msg_id": hex::encode(envelope.msg_id),
        });
        if let (Some(c), Some(kts), Some(obj)) = (p.key_commitment, p.key_ts, rec.as_object_mut()) {
            obj.insert("key_commitment".into(), serde_json::json!(hex::encode(c)));
            obj.insert("key_ts".into(), serde_json::json!(kts));
        }
        let record = serde_json::to_vec(&rec)
            .map_err(|e| RouteResult::Rejected(internal_error("serialize key record", e)))?;

        let input = ChannelKeyArbInput {
            key_scope: p.key_scope,
            channel_id,
            epoch: p.epoch,
            target: &p.target,
            device_id_hex: &p.device_id,
            author: resolved_author,
            key_commitment: p.key_commitment,
            key_ts: p.key_ts,
            envelope_ts: envelope.timestamp,
            msg_id: envelope.msg_id,
            record: &record,
            raw_envelope: raw_bytes,
            now_ms,
            scope_cap: MAX_CHANNEL_KEY_ENVELOPES_PER_SCOPE,
            sync: is_sync,
        };
        match self.storage.arbitrate_and_store_channel_key(&input) {
            Ok(ChannelKeyArbOutcome::Stored) => Ok(Some(KeyStatus::Stored)),
            Ok(ChannelKeyArbOutcome::AlreadyPresent) => Ok(Some(KeyStatus::AlreadyPresent)),
            Ok(ChannelKeyArbOutcome::Conflict(winner)) => {
                Err(RouteResult::KeyConflict(Box::new(KeyConflictInfo {
                    channel_id,
                    epoch: p.epoch,
                    state: crate::storage::key_commits::STATE_ARBITRATED,
                    winner,
                })))
            }
            Ok(ChannelKeyArbOutcome::Rejected(r)) => {
                use crate::storage::key_commits::KeyArbRejection as R;
                let detail = match r {
                    R::CommitmentRequired => "this epoch requires key_commitment and key_ts".to_string(),
                    R::KeyTsStale => "key_ts is more than 15 minutes older than the envelope and is not the current winner".to_string(),
                    R::EpochBelowFloor { floor } => format!("epoch is below the channel key_epoch_floor {floor}"),
                    R::EpochEvicted { below } => format!("epochs below {below} are no longer accepted for this scope"),
                    R::ScopeFull => "the key scope is full".to_string(),
                    R::SyncNotWinner => "sync/backfill may only deliver wraps of the recorded winner or a fresh better-ranked pair".to_string(),
                    R::EpochTooFarAhead { bound } => format!("new epochs above {bound} are not accepted yet"),
                };
                Err(reject(r.code(), &detail))
            }
            Err(e) => Err(RouteResult::Rejected(internal_error("channel key arbitration", e))),
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

    /// Rate-limit check for one message of `author` in `category`. Applies
    /// both the burst and sustained windows (rate-limit rework, l2-node
    /// 0.122.0) — limited if EITHER window is already at its cap. Returns
    /// `None` when allowed (and counts the message in both windows), or
    /// `Some(retry_after_ms)` when limited: the ms until every exceeded
    /// window resets (a window resets once `now - start > window_ms`, so the
    /// value is `start + window_ms + 1 - now`, at least 1). A rejection does
    /// NOT increment the counters, so a retry storm against an exhausted
    /// budget cannot inflate the stored count.
    fn rate_limit_check(
        &self,
        author: &str,
        category: RateCategory,
        registered: bool,
        now_ms: u64,
    ) -> Option<u64> {
        let limits = category.limits(registered, &self.rate_limits_config);
        self.rate_limit_check_key(format!("{}:{:?}", author, category), limits, now_ms)
    }

    /// The dual-window counter behind `rate_limit_check`, for an arbitrary
    /// budget key (also used by the per-(wallet, scope) key-envelope budget).
    fn rate_limit_check_key(&self, key: String, limits: RateLimits, now_ms: u64) -> Option<u64> {
        self.rate_window(key, limits, now_ms, true)
    }

    /// Fixed dual-window counter on the shared `rate_limits` map. See
    /// [`Self::window_check`] for the exact semantics.
    fn rate_window(&self, key: String, limits: RateLimits, now_ms: u64, consume: bool) -> Option<u64> {
        Self::window_check(&self.rate_limits, key, limits, now_ms, consume)
    }

    /// Fixed dual-window counter. A window resets when `now - start >
    /// window_ms` (strictly greater). When a window is at its cap the call
    /// is REFUSED with `Some(retry_after_ms)` = `start + window_ms + 1 -
    /// now` (≥ 1) and nothing is counted — a refused attempt never consumes
    /// a slot. Otherwise `None`; the message is counted only if `consume`
    /// (so a caller can check several buckets first and count all of them
    /// only when every one allows it). Peeks (`consume == false`) and
    /// refusals only READ the map (round-4 audit N4): an attacker's refused
    /// or merely checked attempts never create entries.
    fn window_check(
        map: &DashMap<String, RateLimitEntry>,
        key: String,
        limits: RateLimits,
        now_ms: u64,
        consume: bool,
    ) -> Option<u64> {
        // Effective (burst_count, burst_start, sustained_count, sustained_start)
        // after expiring windows, computed without mutating.
        let view = map.get(&key).map(|e| {
            let (bc, bs) = if now_ms.saturating_sub(e.burst_window_start) > limits.burst_window_ms {
                (0, now_ms)
            } else {
                (e.burst_count, e.burst_window_start)
            };
            let (sc, ss) = if now_ms.saturating_sub(e.sustained_window_start) > limits.sustained_window_ms {
                (0, now_ms)
            } else {
                (e.sustained_count, e.sustained_window_start)
            };
            (bc, bs, sc, ss)
        });
        let (bc, bs, sc, ss) = view.unwrap_or((0, now_ms, 0, now_ms));
        let burst_hit = bc >= limits.burst_max;
        let sustained_hit = sc >= limits.sustained_max;
        if burst_hit || sustained_hit {
            let wait = |start: u64, window: u64| {
                start.saturating_add(window).saturating_add(1).saturating_sub(now_ms)
            };
            let mut retry = 0u64;
            if burst_hit {
                retry = retry.max(wait(bs, limits.burst_window_ms));
            }
            if sustained_hit {
                retry = retry.max(wait(ss, limits.sustained_window_ms));
            }
            return Some(retry.max(1));
        }
        if consume {
            // Re-apply the expiry under the entry lock (another request may
            // have touched it since the read above), then count.
            let mut entry = map.entry(key).or_insert(RateLimitEntry {
                burst_count: 0,
                burst_window_start: now_ms,
                sustained_count: 0,
                sustained_window_start: now_ms,
            });
            if now_ms.saturating_sub(entry.burst_window_start) > limits.burst_window_ms {
                entry.burst_count = 0;
                entry.burst_window_start = now_ms;
            }
            if now_ms.saturating_sub(entry.sustained_window_start) > limits.sustained_window_ms {
                entry.sustained_count = 0;
                entry.sustained_window_start = now_ms;
            }
            entry.burst_count += 1;
            entry.sustained_count += 1;
        }
        None
    }

    /// Step 6 for `ChannelKeyEnvelope` at LOCAL ingress (API / WebSocket).
    /// Two fixed-window buckets, both checked before either is counted so a
    /// refused attempt consumes nothing: per wallet (240/min, both scopes)
    /// and, for channel scope, per (wallet, scope) (60/min, its own map,
    /// pruned every 60 s). Concurrent requests may overshoot by their
    /// concurrency (two independent map entries; bounded, self-correcting).
    fn key_envelope_rate_limit(&self, envelope: &Envelope, author: &str, registered: bool, now_ms: u64) -> Option<u64> {
        self.prune_key_envelope_buckets(now_ms);
        let wallet_key = format!("{}:{:?}", author, RateCategory::KeyEnvelope);
        let wallet_limits = RateCategory::KeyEnvelope.limits(registered, &self.rate_limits_config);
        let scope_key = channel_key_scope(envelope).map(|s| format!("{}:{}", author, hex::encode(s)));
        let mut retry = self.rate_window(wallet_key.clone(), wallet_limits, now_ms, false);
        if let Some(k) = &scope_key {
            if let Some(r) = Self::window_check(&self.local_key_scope_windows, k.clone(), KEY_ENVELOPE_SCOPE_LIMITS, now_ms, false) {
                retry = Some(retry.unwrap_or(0).max(r));
            }
        }
        if retry.is_some() {
            return retry;
        }
        self.rate_window(wallet_key, wallet_limits, now_ms, true);
        if let Some(k) = scope_key {
            Self::window_check(&self.local_key_scope_windows, k, KEY_ENVELOPE_SCOPE_LIMITS, now_ms, true);
        }
        None
    }

    /// Step 6 for `ChannelKeyEnvelope` relayed by GOSSIP (round-4 audit W1):
    /// TOKEN buckets, not fixed windows, sized so they never refuse what an
    /// honest home node admitted — a home node's fixed 60 s window admits
    /// at most 2x its limit in any 60 s span (end of one window + start of
    /// the next): per wallet capacity 720 refilling 4/s (≥ 2 x 240), per
    /// (wallet, channel scope) capacity 180 refilling 1/s (≥ 2 x 60). They
    /// exist only to bound floods by a member that bypasses its home node's
    /// limits (direct gossip publishing). Both buckets are checked before
    /// either is consumed; a refused envelope consumes nothing and creates
    /// no entry. Returns `false` when refused.
    fn gossip_key_envelope_allowed(&self, envelope: &Envelope, author: &str, now_ms: u64) -> bool {
        self.prune_key_envelope_buckets(now_ms);
        let wallet_key = author.to_string();
        let scope_key = channel_key_scope(envelope).map(|s| format!("{}:{}", author, hex::encode(s)));
        let level = |key: &str, spec: BucketSpec| -> f64 {
            match self.gossip_key_buckets.get(key) {
                Some(b) => spec.level(*b, now_ms),
                None => spec.capacity,
            }
        };
        let w = level(&wallet_key, GOSSIP_KEY_WALLET_BUCKET);
        let sc = scope_key.as_deref().map(|k| level(k, GOSSIP_KEY_SCOPE_BUCKET));
        if w < 1.0 || sc.is_some_and(|t| t < 1.0) {
            return false;
        }
        // Hard bound on the map. Entries are only created by ADMITTED
        // envelopes of authorized members; keys that already exist never
        // count against it (round-5 audit N1: a full map must not lock out
        // the very wallets it is tracking). When new keys would overflow,
        // force a prune — at most once per second, so a churn of new
        // wallets cannot turn every envelope into a full-map scan.
        let new_entries = usize::from(!self.gossip_key_buckets.contains_key(&wallet_key))
            + scope_key.as_deref().map_or(0, |k| usize::from(!self.gossip_key_buckets.contains_key(k)));
        if new_entries > 0 && self.gossip_key_buckets.len() + new_entries > GOSSIP_KEY_BUCKETS_MAX {
            let last = self.gossip_forced_prune_ms.load(std::sync::atomic::Ordering::Relaxed);
            if now_ms.saturating_sub(last) >= 1_000
                && self
                    .gossip_forced_prune_ms
                    .compare_exchange(last, now_ms, std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Relaxed)
                    .is_ok()
            {
                self.prune_key_envelope_buckets_now(now_ms);
            }
            if self.gossip_key_buckets.len() + new_entries > GOSSIP_KEY_BUCKETS_MAX {
                return false;
            }
        }
        self.gossip_key_buckets.insert(wallet_key, TokenBucket { tokens: w - 1.0, last_ms: now_ms });
        if let (Some(k), Some(t)) = (scope_key, sc) {
            self.gossip_key_buckets.insert(k, TokenBucket { tokens: t - 1.0, last_ms: now_ms });
        }
        true
    }

    /// Prune the key-envelope bucket maps at most once per 60 s (round-4
    /// audit N6 — the per-scope windows live exactly their 60 s window).
    fn prune_key_envelope_buckets(&self, now_ms: u64) {
        let last = self.key_bucket_last_prune_ms.load(std::sync::atomic::Ordering::Relaxed);
        if now_ms.saturating_sub(last) < KEY_ENVELOPE_SCOPE_LIMITS.burst_window_ms {
            return;
        }
        if self
            .key_bucket_last_prune_ms
            .compare_exchange(last, now_ms, std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Relaxed)
            .is_ok()
        {
            self.prune_key_envelope_buckets_now(now_ms);
        }
    }

    /// Unconditional prune: expired local per-scope windows, and gossip token
    /// buckets that have refilled to capacity (indistinguishable from absent).
    fn prune_key_envelope_buckets_now(&self, now_ms: u64) {
        let window = KEY_ENVELOPE_SCOPE_LIMITS.burst_window_ms;
        self.local_key_scope_windows
            .retain(|_, e| now_ms.saturating_sub(e.burst_window_start) <= window);
        self.gossip_key_buckets.retain(|k, b| {
            // Scope keys contain a ':' (wallet:scope); wallet keys do not.
            let spec = if k.contains(':') { GOSSIP_KEY_SCOPE_BUCKET } else { GOSSIP_KEY_WALLET_BUCKET };
            spec.level(*b, now_ms) < spec.capacity
        });
    }

    /// Whether `author` is rate limited for `category` (counts the message
    /// when allowed). Thin wrapper over `rate_limit_check`.
    #[cfg(test)]
    fn is_rate_limited(
        &self,
        author: &str,
        category: RateCategory,
        registered: bool,
        now_ms: u64,
    ) -> bool {
        self.rate_limit_check(author, category, registered, now_ms).is_some()
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
        // Key-envelope buckets have their own (60 s) pruning; run it here too
        // so an idle node still frees them.
        self.prune_key_envelope_buckets_now(now_ms);
        self.registration_cache
            .retain(|_, (_, cached_at)| now_ms.saturating_sub(*cached_at) < MAX_WINDOW_MS);
    }

    /// Security fix (2026-10-06), closing the `federate_channel`
    /// first-sight-trust residual (l2-node 0.138.0's CHANGELOG): decide
    /// whether a PRIVATE `ChannelCreate` missing `id_derivation_ts` is
    /// still acceptable. `validate_channel_create`/
    /// `verify_private_channel_id_derivation` already checked a PRESENT
    /// derivation; this is purely the absence policy, which needs
    /// storage access (to know whether this is this node's first-ever
    /// encounter with the id) that the pure validator doesn't have.
    ///
    /// - Live (`!is_sync`): always reject if absent. Step 5's timestamp-
    ///   freshness check already ran, so a "legacy" LIVE create is
    ///   impossible by construction — there's no legitimate case to
    ///   grandfather in, so no cutover timestamp is needed or used.
    /// - Synced/backfilled, local `CHANNELS` row already exists: accept
    ///   if absent. This is the pure-merge path
    ///   (`update_indexes`'s existing-row branch), already gated on
    ///   `meta["creator"] == resolved_author` — it cannot steal
    ///   creatorship, so legacy backfill/replay for a channel this node
    ///   ALREADY knows keeps working. (Round-3 re-audit: a non-creator's
    ///   competing `ChannelCreate` here used to still land in
    ///   `CHANNEL_META_MSGS` even though this merge ignored it — closed
    ///   at the indexing site itself, so the "cannot steal creatorship"
    ///   claim now holds for both the `CHANNELS` row AND the bootstrap
    ///   index `channel_bootstrap_envelopes` reads from.)
    /// - Synced/backfilled, no local row (this node's first-ever
    ///   encounter): reject if absent. This is exactly the vulnerable
    ///   case this fix closes — fail closed.
    ///
    /// Deliberately NOT a timestamp-based grandfather window: `is_sync`
    /// skips the drift check entirely, so an attacker delivering a
    /// forged envelope via federate/backfill can freely backdate
    /// `Envelope.timestamp` to land inside any cutover window. Row
    /// existence isn't attacker-forgeable; a timestamp would be.
    fn require_private_id_derivation(
        &self,
        p: &ChannelCreatePayload,
        is_sync: bool,
    ) -> Result<(), validation::ValidationError> {
        if p.channel_type != ChannelType::Private || p.id_derivation_ts.is_some() {
            return Ok(());
        }
        // Security-audit finding (2026-10-06): the config-flag check used
        // to run BEFORE this one, so `require_private_id_derivation =
        // false` also disabled the LIVE-create requirement — contradicting
        // this type's own doc comment, the TOML docs, and the CHANGELOG,
        // all of which say a live create is "always rejected regardless of
        // this flag". That let an operator's legacy-federation unblock
        // silently reopen the full original vulnerability on live
        // traffic (any registered wallet, any unseen private id). The
        // live check is unconditional and must stay first; the flag only
        // ever softens the SYNCED/first-sight branch below.
        if !is_sync {
            return Err(validation::ValidationError(
                "private channel_id derivation required for a live create".into(),
            ));
        }
        if !self.channel_verify_config.require_private_id_derivation {
            return Ok(());
        }
        let row_exists = match self.storage.get_cf(schema::cf::CHANNELS, &p.channel_id.to_be_bytes()) {
            Ok(v) => v.is_some(),
            Err(e) => {
                // Code-audit finding (2026-10-06): a transient storage
                // error used to silently fall through to `false` (reject)
                // with no signal at all — fails closed, the right
                // direction, but invisible to an operator debugging a
                // legitimate backfill that keeps failing.
                warn!(channel_id = p.channel_id, error = %e, "require_private_id_derivation: CHANNELS read failed");
                false
            }
        };
        if row_exists {
            Ok(())
        } else {
            Err(validation::ValidationError(
                "private channel_id derivation required on first encounter with this channel".into(),
            ))
        }
    }

    /// Bounds a Public/ReadPublic `ChannelCreate`'s `channel_id` to
    /// `chain::scanner::PUBLIC_CHANNEL_ID_MARGIN` above the cached
    /// `LAST_KNOWN_CHANNEL_COUNT` (round-5 security audit fix). Mirrors
    /// `PRIVATE_CHANNEL_ID_FLOOR`'s already-proven pattern: bound the
    /// untrusted input's RANGE at ingestion rather than accept anything
    /// and try to make a downstream detection sweep cheaper to abuse —
    /// two prior audit rounds (3.1, 4/5) each found that the sweep-side
    /// approach only reduced an attacker's cost, never removed the
    /// underlying unbounded set. `channel_id` is fully attacker-chosen
    /// with no other bound anywhere in the codebase.
    ///
    /// Fails OPEN when the cache is `0` (unknown) — either
    /// `[channel_verify]` is disabled, or the sweep hasn't completed its
    /// first tick yet — this check must never brick legitimate channel
    /// creation on a fresh or differently-configured node. Private
    /// channels are exempt: their ids are wide-domain hashes with their
    /// own separate floor (`PRIVATE_CHANNEL_ID_FLOOR`), unrelated to the
    /// SC's small sequential space.
    fn validate_channel_id_margin(
        &self,
        p: &ChannelCreatePayload,
    ) -> Result<(), validation::ValidationError> {
        if p.channel_type == ChannelType::Private {
            return Ok(());
        }
        let Ok(Some(bytes)) = self
            .storage
            .get_cf(schema::cf::NODE_STATE, schema::state_keys::LAST_KNOWN_CHANNEL_COUNT)
        else {
            return Ok(());
        };
        let Ok(arr) = <[u8; 8]>::try_from(bytes.as_slice()) else {
            return Ok(());
        };
        // Round-6 audit finding: "unknown" (never written — the sweep
        // hasn't ticked yet, or `[channel_verify]` is disabled) is
        // already handled above by the `Ok(Some(bytes))` match failing
        // and falling through to fail-open. A WRITTEN value of `0` is a
        // real answer — a genuinely fresh network legitimately has zero
        // channels minted — and must be enforced like any other value,
        // not treated as a second "unknown" sentinel (that previously
        // left the bound off entirely on a fresh network until the first
        // channel existed).
        let known_count = u64::from_be_bytes(arr);
        if p.channel_id
            > known_count.saturating_add(crate::chain::scanner::PUBLIC_CHANNEL_ID_MARGIN)
        {
            return Err(validation::ValidationError(
                "channel_id too far above the known on-chain channel count".into(),
            ));
        }
        Ok(())
    }

    /// Validate the payload based on message type.
    fn validate_payload(
        &self,
        envelope: &Envelope,
        resolved_author: &str,
        is_sync: bool,
    ) -> Result<(), validation::ValidationError> {
        match deserialize_payload(envelope.msg_type, &envelope.payload) {
            Ok(payload) => match payload {
                DeserializedPayload::ChatMessage(ref p) => validation::validate_chat_message(p),
                DeserializedPayload::NewsPost(ref p) => validation::validate_news_post(p),
                DeserializedPayload::NewsComment(ref p) => validation::validate_news_comment(p),
                DeserializedPayload::ChannelCreate(ref p) => {
                    validation::validate_channel_create(resolved_author, p)?;
                    self.require_private_id_derivation(p, is_sync)?;
                    self.validate_channel_id_margin(p)
                }
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
                    validation::validate_channel_invite(p)?;
                    validation::validate_channel_invite_expiry(p, envelope.timestamp)
                }
                DeserializedPayload::ChannelJoin(ref p) => validation::validate_channel_join(p),
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
            Err(e) => return Err(internal_error("storage", e)),
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
    fn authorize_channel_action(
        &self,
        envelope: &Envelope,
        resolved_author: &str,
        is_sync: bool,
    ) -> Result<(), String> {
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
            // Private-channel join gate (l2-node 0.140.0). Replaces the old
            // `!has_invite && invite_links_disabled` check, which was always
            // open in practice (`invite_links_disabled` had no writer) and
            // fell through to Ok(()) for an unknown channel. Every private
            // join signed at/after `private_join_proof_activation_ms` must
            // now carry the inviter's signed `ChannelInvite`; see
            // `verify_private_join` for the full rule list. The same check
            // runs again in the apply step (`update_indexes`).
            MessageType::ChannelJoin => {
                let p = rmp_serde::from_slice::<ChannelJoinPayload>(&envelope.payload)
                    .map_err(|e| format!("invalid channel join payload: {}", e))?;
                self.verify_private_join(
                    p.channel_id,
                    resolved_author,
                    envelope.timestamp,
                    p.invite.as_deref(),
                    is_sync,
                )
                .map(|_| ())
            }
            // Creator + any moderator. A channel this node has never seen
            // locally (out-of-order gossip, or — the common case now that
            // ChannelInvite routes to the invitee's dm_topic — a brand-new
            // private channel this node has never federated at all) is
            // deliberately let through here rather than rejected, mirroring
            // `ChannelDelete`'s `channel_creator_check` precedent: neither
            // creator nor moderator status can be checked until the channel
            // actually exists locally, and the cross-node notification
            // delivery this exists for needs the message ACCEPTED
            // regardless. Deferring is safe because an accepted invite
            // GRANTS nothing by itself any more (l2-node 0.140.0 — the
            // `CHANNEL_INVITES` record is no longer written): an invite only
            // ever has an effect when presented inside a `ChannelJoin`, and
            // `verify_private_join` re-verifies the inviter's authority
            // there against whatever the JOINING node knows.
            //
            // For a KNOWN channel a moderator's invite is also accepted on
            // a node that has not (yet) learned the moderator, if it carries
            // a valid creator-signed `inviter_grant` (B5 fix — remote nodes
            // used to reject every moderator-issued invite).
            MessageType::ChannelInvite => {
                let p = rmp_serde::from_slice::<ChannelInvitePayload>(&envelope.payload)
                    .map_err(|e| format!("invalid channel invite payload: {}", e))?;
                match self.channel_gate_info(p.channel_id)? {
                    ChannelGateInfo::Unknown { .. } => Ok(()),
                    ChannelGateInfo::Known { creator, .. } => self.verify_inviter_authority(
                        p.channel_id,
                        creator.as_deref(),
                        resolved_author,
                        envelope.timestamp,
                        p.inviter_grant.as_deref(),
                        envelope.timestamp,
                    )
                    .map(|_| ())
                    .map_err(|e| {
                        // A storage error is an internal failure, not an
                        // authorization verdict (round-2 audit N-i): log it
                        // and surface it as such (`Rejected` is the
                        // router's local/non-penalizing outcome, so a
                        // relaying peer is not punished for our I/O).
                        if e == INTERNAL_ERROR_REASON {
                            // Detail already logged by `internal_error`.
                            e
                        } else {
                            "only creator or moderators can invite users".to_string()
                        }
                    }),
                }
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
                    .map_err(|e| internal_error("storage", e))?
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
                        // The epoch-ahead bound (P2d C1: no near-u64::MAX epochs that
                        // saturate the rotation floor) is enforced in Step 7h instead
                        // (l2-node 0.143.0, `CHANNEL_KEY_EPOCH_MAX_AHEAD`, the same
                        // +256 as before): there it runs under the key lock against the
                        // arbitration state (no TOCTOU), and without the 8192-row
                        // `max_channel_key_epoch` scan this check paid on EVERY
                        // key envelope (round-2 audit W-D/W-E).
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
    /// Verifies, in order (numbered to match the steps in the body):
    /// 1. The target message exists.
    /// 2. The target message deserializes.
    /// 3. The edit/delete's own type corresponds to what `target_id`
    ///    actually is (`ChatEdit`/`ChatDelete` ↔ `ChatMessage`, etc.) —
    ///    security audit, BLOCKING; closes a type-confusion class where e.g.
    ///    a `NewsEdit` could target a `ChatMessage`.
    /// 4. The original author is resolved to a wallet address.
    /// 5. The resolved caller matches that resolved original author.
    /// 6. For a `ChatEdit`: the edit's encrypted-or-plaintext shape matches
    ///    the original's (rejecting a mismatch at write time, not just read
    ///    time), and an encrypted edit doesn't reuse the current effective
    ///    ciphertext's nonce under an unchanged `key_epoch` (AEAD hygiene).
    /// 7. For edits: the edit is within the 30-minute window.
    /// 8. For NewsEdit: the user must be a registered user (exists in USERS CF).
    fn authorize_edit_delete(
        &self,
        envelope: &Envelope,
        resolved_author: &str,
        now_ms: u64,
    ) -> Result<(), String> {
        // Only applies to edit/delete message types
        let (target_id, is_edit, edit_chat_shape) = match envelope.msg_type {
            MessageType::ChatEdit | MessageType::DirectMessageEdit | MessageType::NewsEdit => {
                let payload = rmp_serde::from_slice::<EditPayload>(&envelope.payload)
                    .map_err(|e| format!("failed to deserialize edit payload: {}", e))?;
                // Only meaningful for ChatEdit (checked against the original's
                // own shape below) — DM edits are unconditionally encrypted
                // and NewsEdit has no encrypted-content concept at all, so
                // `None` for those two is simply "not applicable", not
                // "plaintext". Carries the edit's own enc_nonce/key_epoch
                // too, needed for the nonce-reuse check below.
                let edit_chat_shape = if envelope.msg_type == MessageType::ChatEdit {
                    Some((payload.enc_content.is_some(), payload.enc_nonce, payload.key_epoch))
                } else {
                    None
                };
                (payload.target_id, true, edit_chat_shape)
            }
            MessageType::ChatDelete | MessageType::DirectMessageDelete | MessageType::NewsDelete => {
                let payload = rmp_serde::from_slice::<DeletePayload>(&envelope.payload)
                    .map_err(|e| format!("failed to deserialize delete payload: {}", e))?;
                (payload.target_id, false, None)
            }
            _ => return Ok(()), // not an edit/delete message
        };

        // 1. Look up the original message
        let original_bytes = self
            .storage
            .get_cf(schema::cf::MESSAGES, &target_id)
            .map_err(|e| internal_error("storage", e))?
            .ok_or_else(|| "target message not found".to_string())?;

        // 2. Deserialize the original envelope to get its author
        let original_envelope: Envelope = rmp_serde::from_slice(&original_bytes)
            .map_err(|e| format!("failed to deserialize original message: {}", e))?;

        // 3. The edit/delete's own type must correspond to the TARGET's
        // ACTUAL stored type — `target_id` alone is unconstrained across
        // every message type (`EditPayload`/`DeletePayload` are shared
        // structs with no type tag identifying which kind of message they
        // expect to find; any 32-byte id can be written into `target_id`
        // regardless of what it actually points at). Without this, a
        // `NewsEdit` (validated by `validate_news_edit`, which has no
        // encrypted-content concept and only checks plaintext `content`)
        // could target a `ChatMessage` and still reach `ChatMessage`'s
        // type-specific PROJECTION branch in `project_edited_payload`
        // (api/routes.rs) — which dispatches on the ORIGINAL's type, not
        // the edit's — bypassing `validate_chat_edit`'s `MAX_CHAT_CIPHERTEXT`
        // cap, its `key_epoch >= 1` requirement, and the shape-mismatch
        // check below entirely (found by security audit; PoC confirmed a
        // `NewsEdit` writing `enc_content` past the chat cap and
        // `key_epoch: 0` — a value every chat/DM validator explicitly
        // forbids — onto the author's own `ChatMessage`). Checked BEFORE
        // authorship: a type mismatch is rejected regardless of who sent
        // it, so this can't be bypassed by editing/deleting your own
        // wrongly-typed target either.
        let expected_original_type = match envelope.msg_type {
            MessageType::ChatEdit | MessageType::ChatDelete => MessageType::ChatMessage,
            MessageType::DirectMessageEdit | MessageType::DirectMessageDelete => {
                MessageType::DirectMessage
            }
            MessageType::NewsEdit | MessageType::NewsDelete => MessageType::NewsPost,
            // Unreachable given the match above this function that already
            // narrows `envelope.msg_type` to exactly these six variants
            // (anything else returns `Ok(())` before reaching here) — a
            // safe `Err` rather than `unreachable!()`/a panic regardless,
            // since this is a live request-handling path and a future
            // refactor of that outer match must not be able to turn a
            // missed case into a node-crashing panic.
            _ => return Err("not an edit/delete message type".into()),
        };
        if original_envelope.msg_type != expected_original_type {
            return Err(format!(
                "{:?} may only target a {:?}, but the target message is a {:?}",
                envelope.msg_type, expected_original_type, original_envelope.msg_type
            ));
        }

        // 4. Resolve the original author to wallet address
        let original_resolved = self
            .identity
            .resolve(&original_envelope.author)
            .map_err(|e| internal_error("resolve original author", e))?;

        // 5. Verify authorship — only the original author can edit/delete their message
        if resolved_author != original_resolved {
            return Err("only the original author can edit/delete this message".into());
        }

        // 6. For a ChatEdit: reject at WRITE time if its encrypted-or-plaintext
        // shape disagrees with the ORIGINAL message's own shape, rather than
        // silently accepting it and only catching the mismatch later, at READ
        // time, in `project_edited_payload` (api/routes.rs). That function's
        // `None` fail-safe blanks the payload entirely — correct for a
        // genuinely corrupt/adversarial edit, but every shipped client today
        // only ever sends a PLAINTEXT `ChatEdit` (none can build an encrypted
        // one yet — sdk-js/sdk-rust have no `enc_content` on their edit
        // builders), so without this check, an ORDINARY edit of an ORDINARY
        // message in any encrypted channel (the default for new Public/
        // ReadPublic/Private channels) would be accepted, stored, gossiped —
        // and then PERMANENTLY blank that message for every reader the
        // instant it's displayed, where before this feature existed the same
        // edit was merely ineffective (the pre-existing plaintext-only
        // projection silently left the original ciphertext in place). Caught
        // here instead: the sender gets a normal rejected-request error, and
        // the original message is never touched at all.
        //
        // Compared against the ORIGINAL's shape, never the channel's current
        // `encryption_enabled` flag — a channel flipped to encrypted after
        // plaintext messages already exist must still allow those specific
        // messages to keep being edited as plaintext.
        if let Some((edit_is_encrypted, edit_nonce, edit_epoch)) = edit_chat_shape {
            let orig: ChatMessagePayload = rmp_serde::from_slice(&original_envelope.payload)
                .map_err(|e| format!("failed to deserialize original chat message: {}", e))?;
            let orig_is_encrypted = orig.enc_content.is_some();
            if edit_is_encrypted != orig_is_encrypted {
                return Err(if orig_is_encrypted {
                    "cannot edit an encrypted message with a plaintext edit — this client \
                     cannot yet build an encrypted edit for this message"
                        .into()
                } else {
                    "cannot edit a plaintext message with an encrypted edit".into()
                });
            }
            // AEAD hygiene (security audit NOTE, then found incomplete on a
            // further re-audit and closed properly — see below): an edit
            // that reuses the exact same nonce as ANY ciphertext this
            // message has ever carried, under an unchanged key_epoch, would
            // encrypt the new text under the SAME (key, nonce) pair as that
            // ciphertext — for XChaCha20-Poly1305 that breaks
            // confidentiality (the two plaintexts' XOR becomes recoverable
            // from the two ciphertexts) and exposes the reused Poly1305
            // one-time key to forgery. The node never generates nonces
            // itself (all crypto here is client-side; the node only relays
            // ciphertext), so this can only happen from a buggy or
            // malicious client — reject it rather than store and gossip a
            // message carrying a provably-broken ciphertext.
            //
            // Must check against EVERY prior ciphertext, not just the
            // latest: an earlier version of this check compared only
            // against the CURRENT effective ciphertext (the latest edit, or
            // the original if none) — closing "edit₂ reuses edit₁'s nonce"
            // but re-opening two others found on re-audit: once ANY
            // encrypted edit exists, reuse of the ORIGINAL's nonce was no
            // longer checked at all (the very case the original version of
            // this hardening covered), and reuse of any NON-latest prior
            // edit's nonce was never checked. All raw ciphertext stays
            // retrievable in `MESSAGES` regardless of which edit is
            // "current" for projection purposes, so every one of them is a
            // live collision target. `get_edit_history` is capped at 100
            // entries and iterates OLDEST-first, so this check is complete
            // only up to a message's first 100 edits — past that, the
            // oldest 100 are checked and the newest (the ones a buggy
            // client would most likely collide with) are missed. A
            // per-`(target, epoch)` seen-nonce index would close that
            // residual gap but is real added storage cost for an
            // already-narrow, self-inflicted-only edge case (only the
            // message's own author can ever submit a colliding edit).
            if edit_is_encrypted {
                let mut collision = edit_epoch == orig.key_epoch && edit_nonce.is_some() && edit_nonce == orig.enc_nonce;
                if !collision {
                    match self.storage.get_edit_history(&target_id) {
                        Ok(history) => {
                            for (_, prior_edit_id) in history {
                                let prior: Option<EditPayload> = self
                                    .storage
                                    .get_message(&prior_edit_id)
                                    .ok()
                                    .flatten()
                                    .and_then(|bytes| rmp_serde::from_slice::<Envelope>(&bytes).ok())
                                    .and_then(|env| rmp_serde::from_slice::<EditPayload>(&env.payload).ok());
                                if let Some(prior) = prior {
                                    if prior.enc_content.is_some()
                                        && edit_epoch == prior.key_epoch
                                        && edit_nonce.is_some()
                                        && edit_nonce == prior.enc_nonce
                                    {
                                        collision = true;
                                        break;
                                    }
                                }
                            }
                        }
                        // Fail-open on a storage error (availability trade,
                        // matching this message's earlier steps not hard-
                        // failing the whole edit on a transient read issue)
                        // — but logged, since this silently bypasses a
                        // security check rather than merely skipping an
                        // optional enrichment.
                        Err(e) => {
                            tracing::warn!(
                                target = %hex::encode(target_id),
                                error = %e,
                                "nonce-reuse check: could not read edit history, proceeding without it",
                            );
                        }
                    }
                }
                if collision {
                    return Err(
                        "encrypted chat edit must not reuse a nonce this message has already used under the same key_epoch"
                            .into(),
                    );
                }
            }
        }

        // 7. For edits: enforce 30-minute window from original timestamp
        if is_edit {
            const EDIT_WINDOW_MS: u64 = 30 * 60 * 1000;
            if now_ms.saturating_sub(original_envelope.timestamp) > EDIT_WINDOW_MS {
                return Err("edit window expired (30 minutes from original message)".into());
            }
        }

        // 8. For NewsEdit: defense-in-depth check (Step 4d already gates this,
        // but verify on-chain registration here too for edit-specific flow).
        if envelope.msg_type == MessageType::NewsEdit && !self.is_registered(resolved_author) {
            return Err("news edits require on-chain registration".into());
        }

        Ok(())
    }

    /// Authorize `DeletionRequest` (security audit, BLOCKING): a
    /// `SingleMessage` deletion may only target a message the SENDER
    /// themself authored.
    ///
    /// Before this check, `DeletionType::SingleMessage` had NO authorship
    /// gate anywhere: `validate_deletion_request` only checks that
    /// `target_id` is present and non-zero, `authorize_channel_action` falls
    /// through to `Ok(())` for `DeletionRequest`, and the handler
    /// (`update_indexes`) calls `store_deletion_marker(&target_id,
    /// resolved_author, ...)` unconditionally — recording WHO issued the
    /// delete, but never checking that it matches the target's actual
    /// author. `is_deleted` is a bare key-existence check on that marker, so
    /// `enrich_message_json` honors it regardless of who wrote it, and
    /// `DeletionRequest` gossips network-wide. The result: any wallet that
    /// clears `requires_verified_identity()` (on-chain registration — a cost
    /// gate, not an authorship gate) could permanently tombstone ANY
    /// `ChatMessage`, `NewsPost`, or `DirectMessage` on the entire network
    /// just by knowing its `msg_id` (returned in hex in every message
    /// listing) — a working, permissionless censorship/griefing primitive in
    /// a project whose explicit design principle is no censorship. This
    /// mirrors `authorize_edit_delete`'s existing rule for `ChatDelete`/
    /// `DirectMessageDelete`/`NewsDelete` (strict self-authorship, no
    /// moderator exception — `DeletionRequest` has no channel context at
    /// all, so there is no moderator role to except here either); it lives
    /// as a separate function because `DeletionRequest` is not one of the
    /// six type-tagged edit/delete variants `authorize_edit_delete` handles
    /// (it carries no `target_id` type tag, so a target's ACTUAL stored type
    /// is irrelevant here — any type of message the sender authored is a
    /// legitimate target).
    ///
    /// `DeletionType::AllUserContent` needs no equivalent check: it already
    /// scopes itself to `resolved_author`'s own content by construction (it
    /// walks `NEWS_BY_AUTHOR` keyed on the caller's own address), so there is
    /// no attacker-supplied target to authorize.
    ///
    /// A target that cannot be resolved locally is rejected outright rather
    /// than writing a marker for an unknown id — this node has no way to
    /// verify authorship of a message it has never seen, and correct sync/
    /// gossip peers only ever construct a `DeletionRequest` against a
    /// message they can already see.
    fn authorize_deletion_request(
        &self,
        envelope: &Envelope,
        resolved_author: &str,
    ) -> Result<(), String> {
        if envelope.msg_type != MessageType::DeletionRequest {
            return Ok(());
        }
        let payload: DeletionRequestPayload = rmp_serde::from_slice(&envelope.payload)
            .map_err(|e| format!("failed to deserialize deletion request: {}", e))?;
        if payload.delete_type != DeletionType::SingleMessage {
            return Ok(());
        }
        let target_id = match payload.target_id {
            Some(id) => id,
            None => return Ok(()), // validation already requires this to be present for SingleMessage
        };
        let target_bytes = self
            .storage
            .get_cf(schema::cf::MESSAGES, &target_id)
            .map_err(|e| internal_error("storage", e))?
            .ok_or_else(|| "target message not found".to_string())?;
        let target_envelope: Envelope = rmp_serde::from_slice(&target_bytes)
            .map_err(|e| format!("failed to deserialize target message: {}", e))?;
        let target_resolved = self
            .identity
            .resolve(&target_envelope.author)
            .map_err(|e| internal_error("resolve target author", e))?;
        if resolved_author != target_resolved {
            return Err("only the original author can delete this message".into());
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
            .map_err(|e| internal_error("storage", e))?
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
            .map_err(|e| internal_error("resolve original DM sender", e))?;

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
            Err(e) => Err(internal_error("storage", e)),
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
            Err(e) => Err(internal_error("storage", e)),
        }
    }

    /// Check if `address` is a member of `channel_id`. The creator is added as a
    /// member (role "creator") at ChannelCreate, so this covers them too.
    fn is_channel_member(&self, channel_id: u64, address: &str) -> Result<bool, String> {
        let key = schema::encode_channel_member_key(channel_id, address);
        self.storage
            .exists_cf(schema::cf::CHANNEL_MEMBERS, &key)
            .map_err(|e| internal_error("storage", e))
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
            Err(e) => Err(internal_error("storage", e)),
        }
    }

    // ---------------------------------------------------------------
    // Private-channel join gate (l2-node 0.140.0)
    // ---------------------------------------------------------------

    /// The effective `PRIVATE_JOIN_PROOF_ACTIVATION_MS`. Always `0` on
    /// mainnet regardless of config (security audit B1): the grandfather
    /// window exists only for testnet history. Enforced here as well as at
    /// config load so a router built from any config path is safe.
    fn join_proof_activation_ms(&self) -> u64 {
        if self.network == "mainnet" {
            return 0;
        }
        self.channel_verify_config.private_join_proof_activation_ms
    }

    /// Read what the join gate needs about `channel_id`. A storage error
    /// is returned as `Err` (the gate fails CLOSED on it); a corrupt row is
    /// treated as a known PRIVATE channel with no creator, which only ever
    /// makes the gate stricter.
    fn channel_gate_info(&self, channel_id: u64) -> Result<ChannelGateInfo, String> {
        match self.storage.get_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes()) {
            Ok(Some(data)) => match serde_json::from_slice::<serde_json::Value>(&data) {
                Ok(meta) => {
                    let private = match meta.get("channel_type") {
                        Some(serde_json::Value::Number(n)) => n.as_u64() == Some(2),
                        Some(serde_json::Value::String(s)) => s == "Private",
                        _ => false,
                    };
                    let creator = meta
                        .get("creator")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    Ok(ChannelGateInfo::Known { private, creator })
                }
                Err(_) => Ok(ChannelGateInfo::Known { private: true, creator: None }),
            },
            Ok(None) => Ok(ChannelGateInfo::Unknown {
                private: channel_id > PRIVATE_CHANNEL_ID_FLOOR,
            }),
            Err(e) => Err(internal_error("storage", e)),
        }
    }

    /// True when the join gate treats `channel_id` as private: a known row
    /// typed Private, or an unknown id above `PRIVATE_CHANNEL_ID_FLOOR`.
    /// A storage error counts as private (fail closed).
    fn channel_is_private_for_gate(&self, channel_id: u64) -> bool {
        match self.channel_gate_info(channel_id) {
            Ok(ChannelGateInfo::Known { private, .. }) => private,
            Ok(ChannelGateInfo::Unknown { private }) => private,
            Err(_) => true,
        }
    }

    /// Clamp a sender-chosen envelope timestamp before it is stored as a
    /// role watermark: never further in the future than `now + drift`.
    /// The live path already pins timestamps to ±drift; this bounds the
    /// sync path, where a far-future kick/demotion timestamp would
    /// otherwise lock a user out (or kill a grant) until that date.
    fn clamp_watermark_ts(ts: u64) -> u64 {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        ts.min(now_ms.saturating_add(super::envelope::MAX_TIMESTAMP_DRIFT_MS))
    }

    /// Decode + cryptographically verify an EMBEDDED envelope (an invite
    /// inside a join, or a moderator grant inside an invite): size cap,
    /// structure, exact `expected` type, msg_id binding and signature
    /// (`verify_signature`'s ordinary Ogmara/Klever-message path — the
    /// claim-string paths only exist for device/enc types, which `expected`
    /// can never be). Returns the envelope and the wallet its signing key
    /// resolves to. An unknown device key resolves to itself, so an
    /// unresolvable signer can never match a creator/moderator wallet —
    /// the callers' identity comparisons fail closed.
    pub(crate) fn verify_embedded_envelope(
        &self,
        raw: &[u8],
        expected: MessageType,
        max_len: usize,
    ) -> Result<(Envelope, String), String> {
        if raw.is_empty() || raw.len() > max_len {
            return Err(format!("embedded {:?} exceeds {} bytes", expected, max_len));
        }
        let env: Envelope = rmp_serde::from_slice(raw)
            .map_err(|_| format!("embedded {:?} is not a valid envelope", expected))?;
        env.validate_structure()
            .map_err(|e| format!("embedded {:?}: {}", expected, e))?;
        // Type confusion guard: an embedded proof must be EXACTLY the type
        // its slot expects (a join can't smuggle e.g. a ChannelAddModerator
        // as its "invite", and an invite can't nest another invite as its
        // "grant").
        if env.msg_type != expected {
            return Err(format!(
                "embedded envelope is {:?}, expected {:?}",
                env.msg_type, expected
            ));
        }
        self.verify_msg_id(&env)
            .map_err(|e| format!("embedded {:?}: {}", expected, e))?;
        self.verify_signature(&env)
            .map_err(|_| format!("embedded {:?}: signature verification failed", expected))?;
        let signer = self
            .identity
            .resolve(&env.author)
            .map_err(|e| internal_error("embedded envelope identity resolution", e))?;
        Ok((env, signer))
    }

    /// Rules 4-7 of the join gate: the attached invite is a genuine signed
    /// `ChannelInvite` (4), bound to this channel and this joiner (5),
    /// inside its validity window relative to the JOIN's signed timestamp
    /// (6), and issued AFTER the joiner's last kick/ban on this node (7).
    /// Uses envelope timestamps only (never the local clock), so the same
    /// historical join verifies identically on the live and the sync path.
    fn verify_invite_proof(
        &self,
        channel_id: u64,
        joiner: &str,
        join_ts: u64,
        invite_raw: &[u8],
    ) -> Result<VerifiedInvite, String> {
        // Rule 4 — structure + signature + inviter identity.
        let (inv_env, inviter) = self.verify_embedded_envelope(
            invite_raw,
            MessageType::ChannelInvite,
            validation::MAX_JOIN_INVITE_BYTES,
        )?;
        let p = match deserialize_payload(MessageType::ChannelInvite, &inv_env.payload) {
            Ok(DeserializedPayload::ChannelInvite(p)) => p,
            _ => return Err("embedded invite payload is malformed".into()),
        };
        validation::validate_channel_invite(&p).map_err(|e| format!("embedded invite: {}", e))?;
        validation::validate_channel_invite_expiry(&p, inv_env.timestamp)
            .map_err(|e| format!("embedded invite: {}", e))?;

        // Rule 5 — binding. A forwarded invite names someone else.
        if p.channel_id != channel_id {
            return Err("invite is for a different channel".into());
        }
        if p.target_user != joiner {
            return Err("invite is addressed to a different wallet".into());
        }

        // Rule 6 — time, from signed envelope timestamps only. The invite
        // may not be dated (beyond clock skew) after the join that presents
        // it, and the join must not be later than the invite's expiry. The
        // TTL bound itself (ts < exp <= ts + MAX) was checked above.
        let invite_ts = inv_env.timestamp;
        if invite_ts > join_ts.saturating_add(super::envelope::MAX_TIMESTAMP_DRIFT_MS) {
            return Err("invite is dated after the join".into());
        }
        let exp = validation::effective_invite_expiry(&p, invite_ts);
        if join_ts > exp {
            return Err("invite has expired".into());
        }

        // Rule 7 — removal cutoff: an invite issued at or before the
        // joiner's latest kick/ban on this channel is dead (a kicked user
        // can't replay the invite they were originally let in with).
        match self.storage.channel_removal_cutoff(channel_id, joiner) {
            Ok(Some(cutoff)) if invite_ts <= cutoff => {
                return Err("invite predates the joiner's removal from this channel".into());
            }
            Ok(_) => {}
            Err(e) => return Err(internal_error("storage", e)),
        }

        Ok(VerifiedInvite {
            inviter,
            invite_ts,
            inviter_grant: p.inviter_grant,
        })
    }

    /// Verify a raw moderator GRANT (a creator-signed `ChannelAddModerator`
    /// envelope) naming `inviter` as a moderator of `channel_id`, issued no
    /// later than `invite_ts`. Returns the grant's signed timestamp.
    fn verify_moderator_grant(
        &self,
        channel_id: u64,
        creator: &str,
        inviter: &str,
        invite_ts: u64,
        grant_raw: &[u8],
    ) -> Result<u64, String> {
        let (g_env, signer) = self.verify_embedded_envelope(
            grant_raw,
            MessageType::ChannelAddModerator,
            validation::MAX_INVITER_GRANT_BYTES,
        )?;
        if signer != creator {
            return Err("moderator grant is not signed by the channel creator".into());
        }
        let p = match deserialize_payload(MessageType::ChannelAddModerator, &g_env.payload) {
            Ok(DeserializedPayload::ChannelAddModerator(p)) => p,
            _ => return Err("moderator grant payload is malformed".into()),
        };
        if p.channel_id != channel_id {
            return Err("moderator grant is for a different channel".into());
        }
        if p.target_user != inviter {
            return Err("moderator grant names a different wallet than the inviter".into());
        }
        if g_env.timestamp > invite_ts {
            return Err("moderator grant is dated after the invite".into());
        }
        Ok(g_env.timestamp)
    }

    /// Rule 8 of the join gate (also used when a `ChannelInvite` itself is
    /// ingested): is `inviter` entitled to invite into `channel_id`?
    ///   * the creator always is;
    ///   * else a valid creator-signed grant naming the inviter, dated no
    ///     later than the invite, that no stored moderator removal kills.
    ///     A removal kills the grant when `rm_ts > grant_ts` AND
    ///     `rm_ts <= kill_horizon` — callers pass the live join timestamp
    ///     for a live join, and the INVITE timestamp for a synced
    ///     join or an invite ingest (a historical invite issued while the
    ///     inviter was still a moderator stays valid in backfill);
    ///   * else the inviter is listed in local `CHANNEL_MODERATORS` (an
    ///     invite issued before grants existed, on a node that knows the
    ///     moderator).
    fn verify_inviter_authority(
        &self,
        channel_id: u64,
        creator: Option<&str>,
        inviter: &str,
        invite_ts: u64,
        grant: Option<&[u8]>,
        kill_horizon: u64,
    ) -> Result<InviterAuthority, String> {
        if creator == Some(inviter) {
            return Ok(InviterAuthority::Creator);
        }
        let mut grant_error: Option<String> = None;
        if let (Some(grant_raw), Some(creator)) = (grant, creator) {
            match self.verify_moderator_grant(channel_id, creator, inviter, invite_ts, grant_raw) {
                Ok(grant_ts) => {
                    let rm = self
                        .storage
                        .channel_role_watermark(
                            channel_id,
                            schema::role_watermark_kind::MODERATOR_REMOVED,
                            inviter,
                        )
                        .map_err(|e| internal_error("storage", e))?;
                    match rm {
                        Some(rm_ts) if rm_ts > grant_ts && rm_ts <= kill_horizon => {
                            grant_error = Some(
                                "the inviter's moderator grant was revoked".to_string(),
                            );
                        }
                        _ => return Ok(InviterAuthority::Grant { grant_ts }),
                    }
                }
                Err(e) => grant_error = Some(e),
            }
        }
        if self.local_moderator_authorizes(channel_id, inviter, invite_ts)? {
            return Ok(InviterAuthority::LocalModerator);
        }
        if let Some(e) = grant_error {
            debug!(channel_id, inviter, reason = %e, "inviter grant not accepted");
        }
        Err("private channel: inviter is not creator or moderator".to_string())
    }

    /// Rule 8's local-moderator fallback (security audit N3): `inviter` is
    /// listed in `CHANNEL_MODERATORS` AND that listing already covered the
    /// invite's timestamp. A record carries the `grant_ts` of the grant it
    /// came from; an invite signed BEFORE that grant (e.g. while the
    /// moderator was demoted, or before their first promotion) does not
    /// become valid through a later re-promotion. A record written before
    /// 0.140.0 has no `grant_ts`; it is accepted unless a demotion at or
    /// after the invite is recorded. Strict by design: a creator
    /// re-issuing a grant (e.g. to change permissions) invalidates that
    /// moderator's earlier, grant-less invites on nodes that rely on this
    /// fallback — invites carrying their grant are unaffected.
    fn local_moderator_authorizes(
        &self,
        channel_id: u64,
        inviter: &str,
        invite_ts: u64,
    ) -> Result<bool, String> {
        let key = schema::encode_channel_moderator_key(channel_id, inviter);
        let Some(record) = self
            .storage
            .get_cf(schema::cf::CHANNEL_MODERATORS, &key)
            .map_err(|e| internal_error("storage", e))?
        else {
            return Ok(false);
        };
        let grant_ts = serde_json::from_slice::<serde_json::Value>(&record)
            .ok()
            .and_then(|v| v.get("grant_ts").and_then(|t| t.as_u64()));
        match grant_ts {
            Some(g) => Ok(g <= invite_ts),
            None => {
                let demoted = self
                    .storage
                    .channel_role_watermark(
                        channel_id,
                        schema::role_watermark_kind::MODERATOR_REMOVED,
                        inviter,
                    )
                    .map_err(|e| internal_error("storage", e))?;
                Ok(demoted.is_none_or(|m| m < invite_ts))
            }
        }
    }

    /// The `ChannelJoin` membership apply: make `author` a member of
    /// `channel_id` if the channel row exists, `author` is not already a
    /// member, the join passes the private-join gate against current state
    /// (`verify_private_join`, crypto OUTSIDE the lock) and the cheap
    /// authoritative re-checks (`recheck_join_locked`, INSIDE it, right
    /// before the write). Idempotent; failures are logged, never errors.
    fn apply_join_membership(
        &self,
        channel_id: u64,
        author: &str,
        join_ts: u64,
        invite: Option<&[u8]>,
        is_sync: bool,
    ) {
        // Cheap reads first (security audit N2): an unknown channel never
        // gets membership applied, and an existing member is a no-op —
        // neither needs the signature work.
        let row_exists = self
            .storage
            .exists_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes())
            .unwrap_or(false);
        if !row_exists || self.is_channel_member(channel_id, author).unwrap_or(true) {
            return;
        }
        // Full re-verification (crypto) OUTSIDE the lock...
        match self.verify_private_join(channel_id, author, join_ts, invite, is_sync) {
            // ...then only cheap, authoritative re-checks (ban, removal
            // cutoff, inviter authority) INSIDE it, immediately before the
            // write.
            Ok(v) => {
                let _ = self.storage.add_channel_member_checked(
                    channel_id,
                    author,
                    join_ts,
                    "member",
                    || self.recheck_join_locked(channel_id, author, &v),
                );
            }
            Err(reason) => {
                debug!(
                    channel_id,
                    author = %author,
                    %reason,
                    "ChannelJoin accepted earlier but failed the apply-time re-check — membership not applied"
                );
            }
        }
    }

    /// Re-apply a held-back `ChannelJoin` (`join_id`, signed at `join_ts`)
    /// that a later-delivered, OLDER `ChannelLeave` of the same author just
    /// promoted into the metadata index (round-5 audit S-W1). Loads the
    /// stored envelope and runs the normal join apply with sync semantics —
    /// exactly what a late node replaying the index does with it. The join
    /// is re-gated from scratch: the author is no longer a member, so a
    /// private channel needs the join's own invite proof.
    fn reapply_promoted_join(&self, channel_id: u64, author: &str, join_ts: u64, join_id: &[u8; 32]) {
        let Some(env) = self
            .storage
            .get_message(join_id)
            .ok()
            .flatten()
            .and_then(|b| rmp_serde::from_slice::<Envelope>(&b).ok())
        else {
            return;
        };
        if env.msg_type != MessageType::ChannelJoin || env.timestamp != join_ts {
            return;
        }
        let Ok(payload) = rmp_serde::from_slice::<ChannelJoinPayload>(&env.payload) else {
            return;
        };
        if payload.channel_id != channel_id {
            return;
        }
        self.apply_join_membership(channel_id, author, join_ts, payload.invite.as_deref(), true);
    }

    /// The cheap re-check the join apply step (and `federate_channel`'s
    /// final insert) runs INSIDE the membership lock, right before the
    /// member row is written (protocol §3.9.1 "re-check on apply"). No
    /// signature work — `verify_private_join` already did that outside the
    /// lock (security audit N2) — only reads of state that a concurrent
    /// kick/ban/demotion can change: active ban, removal cutoff (rule 7)
    /// and the inviter's authority (rule 8). The removal-vs-join-timestamp
    /// check runs right after this inside `add_channel_member_checked`.
    /// Any storage error fails closed.
    fn recheck_join_locked(&self, channel_id: u64, joiner: &str, v: &VerifiedJoin) -> bool {
        // A join admitted while the channel was unknown never had rule 8
        // evaluated — never apply it, even if the row appeared meanwhile.
        if v.verdict == JoinVerdict::InvitedUnknownChannel {
            return false;
        }
        if self.storage.is_channel_banned(channel_id, joiner).unwrap_or(true) {
            return false;
        }
        let Some(f) = v.invite.as_ref() else { return true };
        match self.storage.channel_removal_cutoff(channel_id, joiner) {
            Ok(Some(cutoff)) if f.invite_ts <= cutoff => return false,
            Ok(_) => {}
            Err(_) => return false,
        }
        match f.authority {
            None | Some(InviterAuthority::Creator) => true,
            Some(InviterAuthority::Grant { grant_ts }) => match self.storage.channel_role_watermark(
                channel_id,
                schema::role_watermark_kind::MODERATOR_REMOVED,
                &f.inviter,
            ) {
                Ok(Some(m)) => !(m > grant_ts && m <= f.kill_horizon),
                Ok(None) => true,
                Err(_) => false,
            },
            Some(InviterAuthority::LocalModerator) => self
                .local_moderator_authorizes(channel_id, &f.inviter, f.invite_ts)
                .unwrap_or(false),
        }
    }

    /// The private-channel join gate (l2-node 0.140.0). Decides whether a
    /// `ChannelJoin` by `joiner` (signed at `join_ts`) may be accepted.
    /// Called from `authorize_channel_action`, AGAIN from the join apply
    /// step (re-check on apply, against fresh state), and from
    /// `federate_channel`. Rules, in order:
    ///
    /// 1. Not private (row typed non-Private, or unknown id at/below the
    ///    floor) → accept; an attached invite is ignored.
    /// 2. Joiner already a member, or the creator → accept (idempotent).
    /// 3. No invite → accept only if `join_ts < activation`, else reject.
    /// 4. Rules 4-7 → `verify_invite_proof`.
    /// 5. Rule 8: channel known → `verify_inviter_authority`; unknown →
    ///    accept structurally, membership is not applied (no row).
    ///
    /// The ban check is NOT here: `check_channel_ban` (Step 7b) already
    /// runs for every `ChannelJoin`, and `federate_channel` calls its own.
    pub(crate) fn verify_private_join(
        &self,
        channel_id: u64,
        joiner: &str,
        join_ts: u64,
        invite: Option<&[u8]>,
        is_sync: bool,
    ) -> Result<VerifiedJoin, String> {
        let plain = |verdict| Ok(VerifiedJoin { verdict, invite: None });
        // Rule 1.
        let info = self.channel_gate_info(channel_id)?;
        let (known, creator) = match info {
            ChannelGateInfo::Known { private: false, .. }
            | ChannelGateInfo::Unknown { private: false } => return plain(JoinVerdict::NotPrivate),
            ChannelGateInfo::Known { private: true, creator } => (true, creator),
            ChannelGateInfo::Unknown { private: true } => (false, None),
        };

        // Rule 2.
        if known
            && (creator.as_deref() == Some(joiner) || self.is_channel_member(channel_id, joiner)?)
        {
            return plain(JoinVerdict::AlreadyMemberOrCreator);
        }

        // Rule 3.
        let Some(invite_raw) = invite else {
            if join_ts < self.join_proof_activation_ms() {
                return plain(JoinVerdict::LegacyBeforeActivation);
            }
            return Err("private channel: invite proof required".into());
        };

        // Rules 4-7.
        let inv = self.verify_invite_proof(channel_id, joiner, join_ts, invite_raw)?;

        // Rule 8.
        let kill_horizon = if is_sync { inv.invite_ts } else { join_ts };
        if !known {
            return Ok(VerifiedJoin {
                verdict: JoinVerdict::InvitedUnknownChannel,
                invite: Some(InviteFacts {
                    inviter: inv.inviter,
                    invite_ts: inv.invite_ts,
                    authority: None,
                    kill_horizon,
                }),
            });
        }
        let authority = self.verify_inviter_authority(
            channel_id,
            creator.as_deref(),
            &inv.inviter,
            inv.invite_ts,
            inv.inviter_grant.as_deref(),
            kill_horizon,
        )?;
        Ok(VerifiedJoin {
            verdict: JoinVerdict::Invited,
            invite: Some(InviteFacts {
                inviter: inv.inviter,
                invite_ts: inv.invite_ts,
                authority: Some(authority),
                kill_horizon,
            }),
        })
    }

    /// `federate_channel`'s pre-fetch gate. Runs BEFORE any outbound DNS/
    /// HTTP request to the caller-supplied host.
    ///
    /// **What it does NOT do (security audit W1, corrected claim):** for a
    /// channel this node does NOT know it cannot verify inviter AUTHORITY —
    /// nobody's creator/moderator status is known yet, and a self-signed
    /// "invite" passes rules 4-7. So it is NOT an SSRF/fetch
    /// barrier against an authenticated caller; the SSRF-validated fetch
    /// stays reachable for any authenticated wallet exactly as in 0.139.0.
    /// That surface is bounded instead by `federate_channel`'s per-wallet
    /// outbound-fetch limit, the fetch concurrency cap, DNS/fetch timeouts,
    /// the per-IP API governor and connect-to-validated-IP pinning.
    ///
    /// What it DOES decide, cheaply:
    ///  * channel KNOWN locally: the caller must already be a member or
    ///    the creator, or attach an invite passing the FULL rules 4-8
    ///    (`now_ms` as the join time) — inviter authority is checkable
    ///    because the creator/moderators are known locally;
    ///  * channel UNKNOWN: no invite is fine (the caller may be the
    ///    creator; `federate_bootstrap_gate` decides after the fetch,
    ///    before anything is stored); an attached invite must pass rules
    ///    4-7 now.
    pub(crate) fn federate_prefetch_gate(
        &self,
        channel_id: u64,
        caller: &str,
        now_ms: u64,
        invite: Option<&[u8]>,
    ) -> Result<(), String> {
        match self.channel_gate_info(channel_id)? {
            // A known NON-private channel needs no invite: the handler
            // answers the specified 400 "only private channels need
            // federation" for it (round-3: this used to 403 a non-member).
            ChannelGateInfo::Known { private: false, .. } => Ok(()),
            ChannelGateInfo::Known { creator, .. } => {
                if creator.as_deref() == Some(caller) || self.is_channel_member(channel_id, caller)? {
                    return Ok(());
                }
                // KNOWN channel (round-2 audit N-b): creator and moderators
                // are known locally, so run the FULL rules 4-8 here — a
                // self-signed invite must not trigger the outbound fetch,
                // the envelope replay or the `federated_from` rewrite.
                let Some(raw) = invite else {
                    return Err("private channel: invite proof required".into());
                };
                let inv = self.verify_invite_proof(channel_id, caller, now_ms, raw)?;
                self.verify_inviter_authority(
                    channel_id,
                    creator.as_deref(),
                    &inv.inviter,
                    inv.invite_ts,
                    inv.inviter_grant.as_deref(),
                    now_ms,
                )
                .map(|_| ())
            }
            // UNKNOWN channel: no invite is fine (the caller may be the
            // creator); an attached invite is checked structurally (4-7)
            // now and fully by `federate_bootstrap_gate` after the fetch.
            ChannelGateInfo::Unknown { .. } => match invite {
                Some(raw) => self.verify_invite_proof(channel_id, caller, now_ms, raw).map(|_| ()),
                None => Ok(()),
            },
        }
    }

    /// `federate_channel`'s verify-then-apply gate for a channel this node
    /// has NEVER seen. Runs on the host's bootstrap `ChannelCreate` BEFORE
    /// `process_synced_message` stores anything, so a rejection leaves no
    /// channel row, no creator member, no federation slot and no topic
    /// subscription behind — by ordering, with no rollback code.
    ///
    /// 1. The envelope is a genuine (msg_id + signature) `ChannelCreate`
    ///    for exactly `channel_id`, typed Private, carrying
    ///    `id_derivation_ts`, whose id matches its Keccak derivation from
    ///    the resolved creator wallet. The derivation is REQUIRED here
    ///    regardless of `[channel_verify] require_private_id_derivation`:
    ///    this path is a member's own entry decision, so a legacy channel
    ///    without the field can only be entered via a node that knows it.
    /// 2. The caller is that creator, OR attached an invite passing rules
    ///    4-8 against that creator (live semantics, `now_ms` = join time).
    pub(crate) fn federate_bootstrap_gate(
        &self,
        create_raw: &[u8],
        channel_id: u64,
        caller: &str,
        now_ms: u64,
        invite: Option<&[u8]>,
    ) -> Result<(), BootstrapGateError> {
        const MAX_BOOTSTRAP_CREATE_BYTES: usize = 16 * 1024;
        let bad = |e: String| BootstrapGateError::BadBootstrap(e);
        let (env, creator) = self
            .verify_embedded_envelope(create_raw, MessageType::ChannelCreate, MAX_BOOTSTRAP_CREATE_BYTES)
            .map_err(bad)?;
        let p = match deserialize_payload(MessageType::ChannelCreate, &env.payload) {
            Ok(DeserializedPayload::ChannelCreate(p)) => p,
            _ => return Err(bad("bootstrap ChannelCreate payload is malformed".into())),
        };
        if p.channel_id != channel_id || p.channel_type != ChannelType::Private {
            return Err(bad("bootstrap ChannelCreate is not this private channel".into()));
        }
        let Some(derivation_ts) = p.id_derivation_ts else {
            return Err(bad("bootstrap ChannelCreate has no id derivation".into()));
        };
        validation::validate_channel_create(&creator, &p).map_err(|e| bad(e.0))?;
        // Belt-and-braces: `validate_channel_create` only checks the
        // derivation when the field is present (it is, by the check above).
        validation::verify_private_channel_id_derivation(&creator, &p.slug, derivation_ts, channel_id)
            .map_err(|e| bad(e.0))?;

        if caller == creator {
            return Ok(());
        }
        let denied = BootstrapGateError::Denied;
        let Some(raw) = invite else {
            return Err(denied("private channel: invite proof required".into()));
        };
        let inv = self.verify_invite_proof(channel_id, caller, now_ms, raw).map_err(denied)?;
        self.verify_inviter_authority(
            channel_id,
            Some(&creator),
            &inv.inviter,
            inv.invite_ts,
            inv.inviter_grant.as_deref(),
            now_ms,
        )
        .map_err(denied)?;
        Ok(())
    }

    /// `federate_channel`'s post-bootstrap gate: the full join gate
    /// (rules 1-8, live semantics with `now_ms` as the join time) plus the
    /// ban check `ChannelJoin` ingest gets from Step 7b. Fixes B2 —
    /// federation used to ignore `CHANNEL_BANS` entirely.
    ///
    /// Known residual (security audit W3, deferred by decision): a node
    /// that federates late, or lags, only knows the kicks/bans/demotions
    /// it has already received — until it has paged through the channel's
    /// metadata via private-channel sync (which delivers every indexed
    /// kick/ban/demotion, see `reconcile::channel_meta_page`) it fails
    /// OPEN on those removals. Bounded by the invite TTL (≤ 14 d)
    /// until then; a node that never completes a metadata pass (no member
    /// peer reachable, no fresh wallet claim) stays bounded only by that
    /// TTL. Closed properly by Phase 2 client-side proof verification.
    pub(crate) fn federate_membership_gate(
        &self,
        channel_id: u64,
        caller: &str,
        now_ms: u64,
        invite: Option<&[u8]>,
    ) -> Result<VerifiedJoin, String> {
        if self
            .storage
            .is_channel_banned(channel_id, caller)
            .map_err(|e| internal_error("storage", e))?
        {
            return Err(format!("user is banned from channel {}", channel_id));
        }
        self.verify_private_join(channel_id, caller, now_ms, invite, false)
    }

    /// `federate_channel`'s final insert (security audit W2): the same
    /// lock-protected, removal-aware insert as a `ChannelJoin` apply, with
    /// `recheck_join_locked` as the in-lock precheck, so a kick/ban/
    /// demotion landing between `federate_membership_gate` and the insert
    /// is honored. `Ok(true)` = added; `Ok(false)` = not added (already a
    /// member, or the re-check / removal cutoff refused).
    pub(crate) fn federate_add_member(
        &self,
        channel_id: u64,
        caller: &str,
        now_ms: u64,
        v: &VerifiedJoin,
    ) -> Result<bool> {
        // The creator federating/refreshing their own channel without a
        // member row is (re)added with role "creator", never "member"
        // (round-3 audit N4) — the same role `ChannelCreate` gives them.
        let role = match self.channel_gate_info(channel_id) {
            Ok(ChannelGateInfo::Known { creator: Some(c), .. }) if c == caller => "creator",
            _ => "member",
        };
        self.storage.add_channel_member_checked(channel_id, caller, now_ms, role, || {
            self.recheck_join_locked(channel_id, caller, v)
        })
    }

    /// True if `address` is in `CHANNEL_MEMBERS` for `channel_id`.
    pub(crate) fn is_member(&self, channel_id: u64, address: &str) -> Result<bool, String> {
        self.is_channel_member(channel_id, address)
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
    /// Returns `true` when this envelope actually CHANGED the author's bot
    /// descriptor (spec 01 §3.11) — the caller uses it to decide whether to emit
    /// `bot_commands_changed`. It is a content comparison, not a "did we store
    /// something" flag: bots republish their descriptor on every start, and a
    /// restart always carries a fresh timestamp, so the LWW watermark alone
    /// would let every restart through to a network-wide broadcast.
    #[cfg(test)]
    fn update_indexes(&self, envelope: &Envelope, resolved_author: &str) -> Result<bool> {
        self.update_indexes_with(envelope, resolved_author, false)
    }

    /// `update_indexes` with the ingest path's `is_sync` flag — the
    /// `ChannelJoin` apply step re-runs the private-join gate and needs the
    /// same live-vs-sync semantics `authorize_channel_action` used.
    fn update_indexes_with(
        &self,
        envelope: &Envelope,
        resolved_author: &str,
        is_sync: bool,
    ) -> Result<bool> {
        // Set by the ProfileUpdate arm; see the doc comment above.
        let mut bot_changed = false;
        // Set by the CHANNEL_META_MSGS index step for a `ChannelJoin` whose
        // author has a held-back `ChannelLeave` NEWER than the join (the
        // leave overtook its join in delivery): the join apply below must
        // not make the author a member.
        let mut join_superseded_by_leave = false;
        // Set by the same index step for a `ChannelLeave` that promoted the
        // author's held-back NEWER `ChannelJoin` (round-5 audit S-W1): the
        // leave apply below removes the member and then re-applies that join,
        // reproducing the leave-then-join replay a late node performs.
        let mut leave_superseded_by_join: Option<(u64, [u8; 32])> = None;
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
                // Moderator propagation (l2-node 0.140.0, B5): index grants
                // and demotions too, so private-channel backfill carries
                // them to a member's home node (which otherwise rejects a
                // moderator's invites/kicks forever). (The moderator-grant
                // endpoint does NOT scan this index — it serves only a
                // record's own `grant_msg_id`.)
                | MessageType::ChannelAddModerator
                | MessageType::ChannelRemoveModerator
        ) {
            // Code-audit finding (2026-10-01, round 3): this used to
            // deserialize into `serde_json::Value` to read just
            // `channel_id` generically. Two independent problems with
            // that, both found auditing the sibling bug in
            // `network::mod::envelope_targets_channel`: (1) JSON has no
            // binary type, so it hard-errors the moment any of these
            // payloads gains a MessagePack "bin" field — none do today,
            // but the next one to add one silently stops being indexed
            // with no error anywhere; (2) a msgpack ARRAY (the wire form
            // `sdk-rust` uses) decodes into `Value::Array`, and
            // `.get("channel_id")` on an array is always `None` — so
            // every array-encoded envelope of these 8 types was NEVER
            // indexed into `CHANNEL_META_MSGS` at all, meaning a
            // backfilling peer could never be served this channel's
            // metadata/membership/moderation history in the first
            // place, regardless of any fix on the requester side.
            // `deserialize_payload` decodes through each type's real,
            // complete struct, which has the right field count for both
            // wire forms.
            if let Ok(payload) =
                crate::messages::types::deserialize_payload(envelope.msg_type, &envelope.payload)
            {
                use crate::messages::types::DeserializedPayload;
                // The `_ => None` arm should be unreachable given the outer
                // `matches!` gate above — logged rather than silently
                // skipped, so a future type added to one list but not the
                // other surfaces instead of silently never being indexed
                // (the exact shape this whole fix was chasing).
                // `removal_target`: the wallet a kick/ban removes — its
                // indexing may promote that wallet's held-back rejoin (see
                // `Storage::index_membership_event`).
                let (cid, removal_target) = match payload {
                    DeserializedPayload::ChannelCreate(p) => (Some(p.channel_id), None),
                    DeserializedPayload::ChannelUpdate(p) => (Some(p.channel_id), None),
                    DeserializedPayload::ChannelJoin(p) => (Some(p.channel_id), None),
                    DeserializedPayload::ChannelLeave(p) => (Some(p.channel_id), None),
                    DeserializedPayload::ChannelDelete(p) => (Some(p.channel_id), None),
                    DeserializedPayload::ChannelKick(p) => (Some(p.channel_id), Some(p.target_user)),
                    DeserializedPayload::ChannelBan(p) => (Some(p.channel_id), Some(p.target_user)),
                    DeserializedPayload::ChannelUnban(p) => (Some(p.channel_id), None),
                    DeserializedPayload::ChannelAddModerator(p) => (Some(p.channel_id), None),
                    DeserializedPayload::ChannelRemoveModerator(p) => (Some(p.channel_id), None),
                    other => {
                        tracing::debug!(
                            msg_type = ?envelope.msg_type,
                            variant = ?other,
                            "update_indexes P-3b: decoded to an unexpected \
                             DeserializedPayload variant for this msg_type — \
                             type-list desync, not indexing into CHANNEL_META_MSGS"
                        );
                        (None, None)
                    }
                };
                if let Some(cid) = cid {
                    // Security-audit finding (2026-10-06, round 3): a
                    // non-creator's competing `ChannelCreate` for an
                    // ALREADY-KNOWN channel_id used to be indexed here
                    // unconditionally — the existing-row merge arm below
                    // only skips the metadata merge for it, it never
                    // suppressed this index. That gave an attacker who
                    // merely knows a channel's id (anyone legitimately
                    // joining also knows it) a standing, real row in
                    // `CHANNEL_META_MSGS`, which they could then backdate
                    // via the sync path (drift check skipped, see Step 5)
                    // to win `channel_bootstrap_envelopes`' earliest/
                    // creator-preferring selection and permanently break
                    // federation for the real channel — the exact DoS
                    // that selection logic was meant to prevent. Checking
                    // the real creator here removes the attacker's
                    // foothold instead of only filtering it downstream;
                    // one extra point read, only for `ChannelCreate`.
                    let is_impostor_create = envelope.msg_type == MessageType::ChannelCreate
                        && self
                            .storage
                            .get_cf(schema::cf::CHANNELS, &cid.to_be_bytes())
                            .ok()
                            .flatten()
                            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                            .and_then(|v| {
                                v.get("creator").and_then(|c| c.as_str()).map(String::from)
                            })
                            .is_some_and(|creator| creator != resolved_author);
                    let membership_event = match envelope.msg_type {
                        MessageType::ChannelJoin => Some(MembershipEvent::Join),
                        MessageType::ChannelLeave => Some(MembershipEvent::Leave),
                        _ => None,
                    };
                    if let Some(event) = membership_event {
                        // Round-4 audit B2: a no-op join/leave (a leave by a
                        // non-member that never joined, an idempotent re-join
                        // by a member) is NOT indexed, and at most
                        // `MAX_INDEXED_MEMBERSHIP_ROWS_PER_AUTHOR` rows are
                        // indexed per (channel, wallet) — a non-member can no
                        // longer flood `CHANNEL_META_MSGS` with leaves and
                        // starve the real joins. Out-of-order rules (a leave
                        // arriving before its join, a rejoin before the
                        // removal it follows) live in
                        // `Storage::index_membership_event`.
                        let outcome = self.storage.index_membership_event(
                            cid,
                            resolved_author,
                            event,
                            envelope.timestamp,
                            &envelope.msg_id,
                        )?;
                        join_superseded_by_leave = outcome.join_superseded_by_leave;
                        leave_superseded_by_join = outcome.leave_superseded_by_join;
                    } else if !is_impostor_create {
                        let key = schema::encode_channel_meta_key(
                            cid,
                            envelope.msg_type_u8(),
                            envelope.timestamp,
                            &envelope.msg_id,
                        );
                        self.storage
                            .put_cf(schema::cf::CHANNEL_META_MSGS, &key, &[])?;
                        if let Some(target) = removal_target.as_deref() {
                            self.storage.index_membership_event(
                                cid,
                                target,
                                MembershipEvent::Removal,
                                envelope.timestamp,
                                &envelope.msg_id,
                            )?;
                        }
                    }
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

                    // Auto-add author as channel member on first message —
                    // PUBLIC channels only (B1 fix, l2-node 0.140.0). For a
                    // private channel this used to be a second, ungated way
                    // in: any wallet that knew the id could post one chat
                    // message and become a member (and so a key-cover
                    // target). The message itself is still accepted — only
                    // the membership side effect is gated. Legacy history
                    // (signed before `private_join_proof_activation_ms`)
                    // keeps the old behaviour so pre-gate backfill converges,
                    // minus any author kicked/banned at or after the message.
                    if !self.channel_is_private_for_gate(payload.channel_id) {
                        let _ = self.storage.add_channel_member(
                            payload.channel_id,
                            resolved_author,
                            envelope.timestamp,
                            "member",
                        );
                    } else if envelope.timestamp < self.join_proof_activation_ms() {
                        let _ = self.storage.add_channel_member_unless_removed(
                            payload.channel_id,
                            resolved_author,
                            envelope.timestamp,
                            "member",
                        );
                    }
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
                    // Only sketch a PUBLIC post whose bucket is (or could still
                    // be) in the rolling window. Public-only (Security Audit
                    // N1): `GET /api/v1/news/hot-topics` is unauthenticated, so
                    // counting `Followers`-only posts would make the hourly
                    // per-tag count a weak existence/volume oracle for hidden
                    // posts. The `news_by_tag` index still gets every tag — the
                    // feed filter re-applies the W37 visibility gate on read.
                    let sketch_this_bucket = ht.enabled
                        && payload.visibility == crate::messages::types::Visibility::Public
                        && {
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
                        return Ok(false);
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
                            // NOTE: this creator claim is UNVERIFIED — a
                            // bare envelope-signer claim, not on-chain-
                            // confirmed. Verification state itself lives
                            // in the separate `CHANNEL_VERIFICATION` CF
                            // (`chain::types::ChannelVerificationState`),
                            // never as a field on this row — see that
                            // type's doc comment for why (anchor
                            // state-root divergence, audit 2026-09-29).
                            // `ChainScanner::sweep_channel_verification`
                            // independently confirms/corrects it for a
                            // public/read-public channel_type; always
                            // stays unverified for a real private channel
                            // (Private never exists on-chain).
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

                        // Audit history (rounds 3-5): a NEW channel_id
                        // landing here that's ≤ `sweep_channel_
                        // verification`'s priority-lane high-water mark
                        // would otherwise never be looked at again by
                        // that lane — it only ever walks FORWARD.
                        // Two successive attempts to close this
                        // out-of-band (rewinding the shared high-water
                        // mark, then a capped per-id "pending recheck"
                        // queue) each turned out to be their OWN
                        // attacker-exploitable resource: the rewind let
                        // one message force a weeks-long re-walk of the
                        // whole covered range; the queue's global cap
                        // and FIFO drop-newest behavior let an attacker
                        // fill it with junk so their OWN real target
                        // was the one silently dropped (round-5 security
                        // audit). Round 5 removes the out-of-band path
                        // entirely rather than build a third, more
                        // complex version of the same shape — this
                        // specific timing window (a forger submitting
                        // right after the priority lane passes a given
                        // id) now converges via the round-robin lane's
                        // own cadence instead, the SAME already-accepted
                        // "detection, not instant closure" posture this
                        // feature already carries for tombstone-poisoning
                        // and for a `ChannelTransferred` lost to a scan
                        // gap (see CHANGELOG "Known limitations").

                        // W14: this is the first time this channel_id's creator has
                        // become known on this node — consume any pending delete claim
                        // recorded while the channel was still unknown. A match means
                        // the real creator already asked to delete it (we just hadn't
                        // seen the create yet); converge straight to deleted instead of
                        // momentarily resurrecting it. A mismatch (or no claim) is a
                        // silent no-op — the claim is gone either way, one-shot.
                        if let Ok(claim) = self.storage.take_pending_channel_delete(payload.channel_id) {
                            if channel_delete_claim_matches(claim.as_ref(), resolved_author) {
                                self.storage.tombstone_channel(
                                    payload.channel_id,
                                    envelope.timestamp,
                                    Some(resolved_author),
                                )?;
                            }
                        }
                    }
                }
            }
            MessageType::ChannelJoin => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelJoinPayload>(&envelope.payload)
                {
                    // Re-check on apply (private-channel join gate, l2-node
                    // 0.140.0): `authorize_channel_action` ran before this
                    // envelope was stored, against state that may have moved
                    // since (a concurrent kick/ban/demotion). The full
                    // re-check runs UNDER the membership lock, and the add
                    // happens only if no kick/ban at or after
                    // the join's own timestamp is recorded — on the backfill
                    // path a kick can be applied BEFORE the join it
                    // supersedes, and the join must not resurrect the user.
                    // Idempotent: a no-op if already a member or the channel
                    // is unknown (deferred joins never apply membership).
                    // See `apply_join_membership` (shared with the S-W1
                    // re-apply of a promoted join after a late leave).
                    if join_superseded_by_leave {
                        debug!(
                            channel_id = payload.channel_id,
                            author = %resolved_author,
                            "ChannelJoin superseded by the author's own newer ChannelLeave (delivered out of order) — membership not applied"
                        );
                    } else {
                        self.apply_join_membership(
                            payload.channel_id,
                            resolved_author,
                            envelope.timestamp,
                            payload.invite.as_deref(),
                            is_sync,
                        );
                    }
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
                    // Round-5 audit S-W1: the author's own NEWER join was
                    // delivered before this leave and held back as a no-op
                    // re-join (it was still a member then). The index step
                    // just promoted it, so a late node replays leave → join;
                    // re-apply it here so this node converges to the same
                    // state (member iff that join passes the gate on its own
                    // now). Kick/ban deliberately get no such re-apply.
                    if let Some((join_ts, join_id)) = leave_superseded_by_join {
                        self.reapply_promoted_join(payload.channel_id, resolved_author, join_ts, &join_id);
                    }
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
                            self.storage.tombstone_channel(
                                payload.channel_id,
                                envelope.timestamp,
                                Some(resolved_author),
                            )?;
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
                    // Moderator propagation (l2-node 0.140.0): also record
                    // WHICH signed envelope granted this role, so the
                    // moderator can fetch it (`GET .../moderators/{addr}/
                    // grant`) and attach it to invites as `inviter_grant`.
                    // Extra key alongside the permission flags — every
                    // reader looks fields up by name, so this is additive.
                    //
                    // Now that backfill also replays moderator messages,
                    // ordering matters: (a) a grant OLDER than the one
                    // already recorded never replaces it (`grant_ts` LWW —
                    // spec 03: "replaced only by a grant with a NEWER signed
                    // timestamp"; records from before 0.140.0 carry no
                    // `grant_ts` and are always replaced), and (b) a grant
                    // at or before a known demotion of the same wallet
                    // (`moderator_removed` watermark) must not reinstate it.
                    let demoted_after = self
                        .storage
                        .channel_role_watermark(
                            payload.channel_id,
                            schema::role_watermark_kind::MODERATOR_REMOVED,
                            &payload.target_user,
                        )?
                        .is_some_and(|m| m >= envelope.timestamp);
                    let newer_recorded = self
                        .storage
                        .get_cf(schema::cf::CHANNEL_MODERATORS, &key)?
                        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                        .and_then(|v| v.get("grant_ts").and_then(|t| t.as_u64()))
                        .is_some_and(|t| t >= envelope.timestamp);
                    if !demoted_after && !newer_recorded {
                        let mut perms = serde_json::to_value(&payload.permissions)
                            .context("serializing moderator permissions")?;
                        if let Some(obj) = perms.as_object_mut() {
                            obj.insert(
                                "grant_msg_id".into(),
                                serde_json::json!(hex::encode(envelope.msg_id)),
                            );
                            obj.insert("grant_ts".into(), serde_json::json!(envelope.timestamp));
                        }
                        let perms = serde_json::to_vec(&perms)
                            .context("serializing moderator record")?;
                        self.storage
                            .put_cf(schema::cf::CHANNEL_MODERATORS, &key, &perms)?;
                    }
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
                    // Private-channel join gate: remember WHEN this wallet
                    // was demoted (MAX watermark) so a grant it was issued
                    // earlier stops authorizing new invites/joins
                    // (`verify_inviter_authority`).
                    self.storage.raise_channel_role_watermark(
                        payload.channel_id,
                        schema::role_watermark_kind::MODERATOR_REMOVED,
                        &payload.target_user,
                        Self::clamp_watermark_ts(envelope.timestamp),
                    )?;
                    // Symmetric to the AddModerator LWW above: a demotion
                    // OLDER than the currently recorded grant (backfill
                    // replaying history out of order) must not delete it.
                    let newer_grant = self
                        .storage
                        .get_cf(schema::cf::CHANNEL_MODERATORS, &key)?
                        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                        .and_then(|v| v.get("grant_ts").and_then(|t| t.as_u64()))
                        .is_some_and(|t| t > envelope.timestamp);
                    if !newer_grant {
                        self.storage
                            .delete_cf(schema::cf::CHANNEL_MODERATORS, &key)?;
                    }
                }
            }
            MessageType::ChannelKick => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelKickPayload>(&envelope.payload)
                {
                    // Private-channel join gate (B3 fix): record the kick as
                    // a MAX watermark BEFORE removing the member, so a join
                    // racing this removal can never be re-added after it
                    // (`add_channel_member_unless_removed` reads this under
                    // the same lock) and an old invite can't be replayed to
                    // rejoin (`verify_invite_proof` rule 7).
                    self.storage.raise_channel_role_watermark(
                        payload.channel_id,
                        schema::role_watermark_kind::REMOVED,
                        &payload.target_user,
                        Self::clamp_watermark_ts(envelope.timestamp),
                    )?;
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
                    // Same `removed` watermark as ChannelKick above (it
                    // outlives an Unban: a rejoin after an unban needs an
                    // invite issued after the ban).
                    self.storage.raise_channel_role_watermark(
                        payload.channel_id,
                        schema::role_watermark_kind::REMOVED,
                        &payload.target_user,
                        Self::clamp_watermark_ts(envelope.timestamp),
                    )?;
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
                    // At the per-channel cap, FIFO — remove the oldest pin
                    if pin_count as usize >= validation::MAX_PINS_PER_CHANNEL {
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
                        validation::MAX_PINS_PER_CHANNEL,
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
            // ChannelInvite has NO apply-step side effect any more (l2-node
            // 0.140.0, B4). It used to write a `CHANNEL_INVITES` row that
            // `ChannelJoin` trusted as bare proof of invitation — a derived
            // grant that was never pruned and (with `invite_links_disabled`
            // never written) never actually consulted for anything. The
            // signed invite envelope itself is now the proof: it is stored
            // in `MESSAGES` like every accepted message, surfaced to the
            // invitee via `GET /api/v1/notifications` (`invite_envelope`),
            // and verified in full when presented inside a `ChannelJoin`.
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
                    // Merge updated fields into existing channel metadata.
                    // Audit 2026-09-29 (HIGH finding): this read-modify-
                    // write used to be unlocked, so it could race
                    // `ChainScanner::verify_one_channel_creator`'s
                    // locked apply (or any other locked writer) and
                    // silently drop this update, or have ITS OWN write
                    // silently dropped by one that lands after this read
                    // but before this write. `with_channel_membership_
                    // lock` closes that for this specific interaction —
                    // see `Storage::apply_channel_verification_result`'s
                    // doc comment for the remaining unlocked writers.
                    let key = payload.channel_id.to_be_bytes();
                    self.storage.with_channel_membership_lock(|| -> Result<()> {
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
                    Ok(())
                    })?;
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
                    // LWW key: the client's cleartext content timestamp, or the
                    // signed envelope time for an older client that omits it.
                    // This blob is gossiped on `topic_profile`, so the SAME
                    // envelope is applied again on every peer node — the LWW
                    // guard makes that idempotent and stops an out-of-order
                    // relay (or a stale re-seed of a fresh node) rolling it back.
                    let ts = if payload.updated_at > 0 {
                        payload.updated_at
                    } else {
                        envelope.timestamp
                    };
                    let applied = self.storage.store_settings(
                        resolved_author,
                        json.to_string().as_bytes(),
                        ts,
                    )?;
                    debug!(author = %resolved_author, applied, ts, "Settings synced");
                }
            }
            MessageType::KeyVaultSync => {
                // E2E P3 (protocol §2.5): store the wallet-encrypted key-recovery
                // vault. Opaque to the node; persisted as JSON so the owner can
                // retrieve {encrypted_vault, nonce, format_version} for restore.
                // Last-write-wins per wallet — only the verified signer can write
                // their own record (auth is the envelope signature). Gossiped on
                // `topic_profile` so a fresh device restores it from ANY node.
                if let Ok(payload) =
                    rmp_serde::from_slice::<KeyVaultSyncPayload>(&envelope.payload)
                {
                    let json = serde_json::json!({
                        "encrypted_vault": payload.encrypted_vault,
                        "nonce": payload.nonce,
                        "format_version": payload.format_version,
                    });
                    let ts = if payload.updated_at > 0 {
                        payload.updated_at
                    } else {
                        envelope.timestamp
                    };
                    let applied = self.storage.store_key_vault(
                        resolved_author,
                        json.to_string().as_bytes(),
                        ts,
                    )?;
                    debug!(author = %resolved_author, applied, ts, "Key vault synced");
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
                                // l2-node 0.142.0: keep the wallet's binding
                                // signature (verified at `verify_device_enc_claim`
                                // over `ogmara-enc-bind:{network}:{enc_pub}:
                                // {device_id}:{wallet}:{ts}`) so `GET enc-keys`
                                // can serve it and clients can verify the key is
                                // wallet-bound without trusting this node.
                                // Additive JSON field: older rows simply lack it.
                                let record = serde_json::json!({
                                    "enc_pub": enc_pub,
                                    "device_id": device_id,
                                    "created_at": envelope.timestamp,
                                    "ts": envelope.timestamp,
                                    "revoked": false,
                                    "wallet_signature": base64::Engine::encode(
                                        &base64::engine::general_purpose::STANDARD,
                                        &envelope.signature,
                                    ),
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
                            return Ok(false);
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
                            return Ok(false);
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
                        return Ok(false);
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
                // l2-node 0.143.0: channel-scope envelopes are fully
                // arbitrated AND stored by Step 7h (`arbitrate_channel_key`) —
                // nothing left to apply here. Only DM scope continues.
                if let Some(p) =
                    rmp_serde::from_slice::<ChannelKeyEnvelopePayload>(&envelope.payload)
                        .ok()
                        .filter(|p| p.scope_kind != crate::messages::types::key_scope_kind::CHANNEL)
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
                        // l2-node 0.143.0: lets `GET /keys/{scope}?proof=1`
                        // serve the original signed envelope.
                        "msg_id": hex::encode(envelope.msg_id),
                    }))
                    .context("serializing channel key envelope")?;
                    // DM keys are PER-SENDER (keyed by the publishing author so each
                    // participant's conv_key coexists). (Channel epoch keys are a single
                    // group key stored author-agnostically by Step 7h.)
                    let store_author = resolved_author;
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
                        return Ok(false);
                    }

                    // Capture old display_name BEFORE merge so we can clean up the
                    // USERS_BY_NAME prefix index if the name actually changed.
                    let old_name = record
                        .get("display_name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    // Snapshot the bot descriptor BEFORE the merge so we can tell a
                    // real change from a no-op republish. Deliberately EXCLUDES
                    // `bot_updated_at`, which moves on every republish and would make
                    // every comparison report a change.
                    let bot_snapshot = |r: &serde_json::Value| {
                        (
                            r.get("is_bot").and_then(|v| v.as_bool()).unwrap_or(false),
                            r.get("bot_handle").cloned().unwrap_or(serde_json::Value::Null),
                            r.get("bot_commands").cloned().unwrap_or(serde_json::Value::Null),
                        )
                    };
                    let old_bot = bot_snapshot(&record);

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
                        // Bot descriptor (spec 01 §3.11). Absent `bot` means
                        // UNCHANGED — never "clear" — so a plain display-name edit
                        // from an ordinary client cannot wipe a bot's command list.
                        if let Some(bot) = &payload.bot {
                            if !bot.is_bot {
                                // `is_bot: false` is the explicit un-declare: it
                                // clears the whole descriptor, not just the flag.
                                map.insert("is_bot".into(), serde_json::json!(false));
                                map.insert("bot_handle".into(), serde_json::Value::Null);
                                map.insert("bot_commands".into(), serde_json::json!([]));
                            } else {
                                map.insert("is_bot".into(), serde_json::json!(true));
                                // `handle: None` leaves an existing handle alone.
                                if let Some(h) = &bot.handle {
                                    map.insert("bot_handle".into(), serde_json::json!(h));
                                }
                                // `commands: None` leaves the stored list alone;
                                // `Some([])` clears it. These are different requests
                                // and must not collapse into one.
                                if let Some(cmds) = &bot.commands {
                                    map.insert("bot_commands".into(), serde_json::json!(cmds));
                                }
                            }
                            // Informational only. The authoritative anti-replay
                            // watermark stays `profile_updated_at` above — a second
                            // LWW key on the same record is how you get two truths.
                            map.insert(
                                "bot_updated_at".into(),
                                serde_json::json!(envelope.timestamp),
                            );
                        }
                        // Record the LWW watermark for the next apply.
                        map.insert(
                            "profile_updated_at".into(),
                            serde_json::json!(envelope.timestamp),
                        );
                    }

                    // Content comparison gates the BROADCAST; the LWW check above
                    // gates the REPLAY. Both are required: a bot restart produces a
                    // fresh timestamp (so LWW passes) carrying an identical
                    // descriptor (so this suppresses), which is what makes
                    // republish-on-start free.
                    bot_changed = payload.bot.is_some() && bot_snapshot(&record) != old_bot;

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
                        return Ok(false);
                    }

                    // Validate payload bounds
                    if payload.channels.len() > 10_000 {
                        warn!(node_id = %payload.node_id, count = payload.channels.len(),
                            "NodeAnnouncement channels list too large — rejecting");
                        return Ok(false);
                    }
                    if let Some(ref ep) = payload.api_endpoint {
                        if ep.len() > 256
                            || (!ep.starts_with("http://") && !ep.starts_with("https://"))
                        {
                            warn!(node_id = %payload.node_id,
                                "NodeAnnouncement invalid api_endpoint — rejecting");
                            return Ok(false);
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
                            return Ok(false);
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

        Ok(bot_changed)
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
            key_commitment: None,
            key_ts: None,
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
        assert!(r.authorize_channel_action(&env, creator, false).is_ok());
    }

    #[test]
    fn channel_key_authz_rejects_non_member_author() {
        let (r, _d) = router();
        let (cid, creator, member, outsider) = (7u64, "klv1creator", "klv1member", "klv1outsider");
        make_channel(&r, cid, creator);
        add_member(&r, cid, member);
        let scope = crate::crypto::compute_channel_scope(cid);
        let env = channel_key_env(cid, scope, outsider, member);
        assert!(r.authorize_channel_action(&env, outsider, false).is_err());
    }

    #[test]
    fn channel_key_authz_rejects_non_member_target() {
        let (r, _d) = router();
        let (cid, creator, outsider) = (7u64, "klv1creator", "klv1outsider");
        make_channel(&r, cid, creator);
        let scope = crate::crypto::compute_channel_scope(cid);
        let env = channel_key_env(cid, scope, creator, outsider);
        assert!(r.authorize_channel_action(&env, creator, false).is_err());
    }

    #[test]
    fn channel_key_authz_rejects_scope_mismatch() {
        let (r, _d) = router();
        let (cid, creator) = (7u64, "klv1creator");
        make_channel(&r, cid, creator);
        // key_scope for a DIFFERENT channel → reject even though author is a member.
        let wrong_scope = crate::crypto::compute_channel_scope(999);
        let env = channel_key_env(cid, wrong_scope, creator, creator);
        assert!(r.authorize_channel_action(&env, creator, false).is_err());
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

    fn signed_invite_envelope(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        channel_id: u64,
        target_user: &str,
        timestamp: u64,
    ) -> Vec<u8> {
        let payload = ChannelInvitePayload {
            channel_id,
            target_user: target_user.to_string(),
            anchor_node: Some("https://host.example".to_string()),
            expires_at: None,
            inviter_grant: None,
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id =
            crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ChannelInvite as u8,
            &msg_id,
            timestamp,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChannelInvite,
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

    /// Security fix (2026-10-06): private channel_id must now verify
    /// against `Keccak-256(author + slug + id_derivation_ts) %
    /// (2^53-1)` on a LIVE create (`process_message`, what every caller
    /// of this helper uses) — an arbitrary caller-chosen `channel_id`
    /// would now be rejected, breaking every test using this helper for
    /// unrelated reasons (invite trust, delete/resurrection convergence).
    /// Derives a genuinely-matching `channel_id` from `(author, slug,
    /// timestamp)` instead of accepting one, and returns it so callers
    /// use the real value rather than an arbitrary one.
    fn signed_create_envelope(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        slug: &str,
        timestamp: u64,
    ) -> (Vec<u8>, u64) {
        const JS_SAFE_INTEGER_MODULUS: u64 = (1u64 << 53) - 1;
        // Re-roll (bump the derivation ts) on the ~1-in-2^21 chance the
        // derived id lands at/below the floor — same retry the real
        // client-side fix applies, so this test helper can't flake.
        let mut candidate_ts = timestamp;
        let (channel_id, timestamp) = loop {
            let preimage = format!("{author}{slug}{candidate_ts}");
            let hash = crypto::keccak256(preimage.as_bytes());
            let raw = u64::from_be_bytes([
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            ]);
            let candidate_id = raw % JS_SAFE_INTEGER_MODULUS;
            if candidate_id > crate::messages::types::PRIVATE_CHANNEL_ID_FLOOR {
                break (candidate_id, candidate_ts);
            }
            candidate_ts += 1;
        };
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
            id_derivation_ts: Some(timestamp),
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
        (rmp_serde::to_vec_named(&envelope).unwrap(), channel_id)
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
    fn invite_for_unknown_channel_is_accepted_not_rejected() {
        // Cross-node private-channel invite fix: a node that has never
        // federated the target channel can't verify creator/moderator
        // status locally, so authorization must defer (mirroring
        // `channel_creator_check`'s existing ChannelDelete precedent)
        // rather than hard-reject — otherwise a relayed ChannelInvite on
        // the invitee's dm_topic would never produce a notification on any
        // node except the one that already knows the channel, which is
        // exactly the bug this fix closes.
        let (r, _d) = router();
        let sk = crypto::generate_keypair();
        let inviter = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &inviter, 1_000);
        let cid = 4244u64;

        let raw = signed_invite_envelope(&sk, &inviter, cid, "klv1target", now_ms());
        match r.process_message(&raw) {
            RouteResult::Accepted { .. } => {}
            other => panic!("expected Accepted (deferred, not rejected), got {:?}", other),
        }
    }

    #[test]
    fn invite_for_unknown_channel_never_grants_a_trusted_channel_invites_record() {
        // REGRESSION GUARD, CRITICAL (security audit, 2026-09-15). The
        // deferred-Unknown authorization above must NOT, by itself, let an
        // unverifiable invite write the CHANNEL_INVITES record ChannelJoin
        // trusts as bare proof of a real invite — otherwise ANY wallet could
        // self-grant "invited" status on ANY private channel (including
        // inviting itself) just by targeting a node that hasn't federated
        // that channel yet, bypassing invite_links_disabled entirely. The
        // message is Accepted (so the notification still gets delivered —
        // that's the actual fix), but no CHANNEL_INVITES row may exist for
        // an unknown channel's invite.
        let (r, _d) = router();
        let attacker_sk = crypto::generate_keypair();
        let attacker = crypto::pubkey_to_address(&attacker_sk.verifying_key()).unwrap();
        register_user(&r, &attacker, 1_000);
        let cid = 4246u64;

        // Self-invite: the worst-case variant from the finding.
        let raw = signed_invite_envelope(&attacker_sk, &attacker, cid, &attacker, now_ms());
        assert!(matches!(r.process_message(&raw), RouteResult::Accepted { .. }));

        let key = schema::encode_channel_invite_key(cid, &attacker);
        assert!(
            r.storage.get_cf(schema::cf::CHANNEL_INVITES, &key).unwrap().is_none(),
            "an invite for a channel this node has never seen must NOT be trusted as a real grant"
        );
    }

    #[test]
    fn invite_for_a_known_channel_by_the_real_creator_is_accepted_but_writes_no_record() {
        // l2-node 0.140.0 (private-channel join gate, B4): a real creator's
        // invite for a known channel is still ACCEPTED (stored + notified),
        // but the node no longer writes a `CHANNEL_INVITES` grant row — the
        // signed invite itself is the proof a later ChannelJoin carries.
        let (r, _d) = router();
        let creator_sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&creator_sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);
        let (create_raw, cid) = signed_create_envelope(&creator_sk, &creator, "test-channel", now_ms());
        assert!(matches!(r.process_message(&create_raw), RouteResult::Accepted { .. }));

        let raw = signed_invite_envelope(&creator_sk, &creator, cid, "klv1target", now_ms() + 1);
        assert!(matches!(r.process_message(&raw), RouteResult::Accepted { .. }));

        let key = schema::encode_channel_invite_key(cid, "klv1target");
        assert!(
            r.storage.get_cf(schema::cf::CHANNEL_INVITES, &key).unwrap().is_none(),
            "0.140.0+: an accepted invite must not write a CHANNEL_INVITES record"
        );
    }

    #[test]
    fn invite_for_a_known_channel_by_a_non_creator_non_moderator_is_rejected() {
        // The Unknown-defers change must not weaken the KNOWN-channel case:
        // a channel this node DOES have a record for still requires the
        // author to be its creator or a moderator.
        let (r, _d) = router();
        let creator_sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&creator_sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);
        // See the sibling test above re: `signed_create_envelope`'s
        // self-derived channel_id.
        let (create_raw, cid) = signed_create_envelope(&creator_sk, &creator, "test-channel", now_ms());
        assert!(matches!(r.process_message(&create_raw), RouteResult::Accepted { .. }));

        let outsider_sk = crypto::generate_keypair();
        let outsider = crypto::pubkey_to_address(&outsider_sk.verifying_key()).unwrap();
        register_user(&r, &outsider, 1_000);
        let invite_raw =
            signed_invite_envelope(&outsider_sk, &outsider, cid, "klv1target", now_ms() + 1);
        match r.process_message(&invite_raw) {
            RouteResult::Rejected(_) => {}
            other => panic!("expected Rejected (not creator/moderator), got {:?}", other),
        }
    }

    #[test]
    fn later_create_by_same_wallet_converges_to_deleted() {
        let (r, _d) = router();
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);
        // Build both envelopes up front (the create's self-derived id is
        // needed to target the delete at the SAME channel), but PROCESS
        // them in the original order (delete claim first, then the real
        // create) — that processing order is what this test exercises.
        let (create_raw, cid) = signed_create_envelope(&sk, &creator, "test-channel", now_ms() + 1);
        let delete_raw = signed_delete_envelope(&sk, &creator, cid, now_ms());

        assert!(matches!(r.process_message(&delete_raw), RouteResult::Accepted { .. }));
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
        // Build the real creator's envelope first to learn the (self-
        // derived) channel_id the attacker will "guess" — then process
        // in the original order (attacker's delete claim first, real
        // create second).
        let (create_raw, cid) =
            signed_create_envelope(&real_creator_sk, &real_creator, "test-channel", now_ms() + 1);

        // Attacker guesses the not-yet-used channel_id and claims to delete it.
        let delete_raw = signed_delete_envelope(&attacker_sk, &attacker, cid, now_ms());
        assert!(matches!(r.process_message(&delete_raw), RouteResult::Accepted { .. }));

        // The real creator later actually creates it.
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

    /// Code-audit finding (2026-10-01, round 3): `update_indexes`'s P-3b
    /// block used to deserialize into `serde_json::Value` to read
    /// `channel_id` for `CHANNEL_META_MSGS` indexing. A msgpack ARRAY (the
    /// wire form `sdk-rust` uses) decodes into `Value::Array`, and
    /// `.get("channel_id")` on an array is always `None` — so an
    /// array-encoded `ChannelCreate` was accepted and stored in MESSAGES
    /// (the envelope itself decodes fine via its full, real struct) but
    /// NEVER indexed into `CHANNEL_META_MSGS`, meaning a backfilling peer
    /// could never be served this channel's metadata at all. This pins the
    /// fix: decoding through `deserialize_payload` indexes the array form
    /// too.
    #[test]
    fn array_encoded_channel_create_is_indexed_into_channel_meta_msgs() {
        let (r, _d) = router();
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);

        let channel_id = 4247u64;
        let timestamp = now_ms();
        let payload = ChannelCreatePayload {
            channel_id,
            slug: "general".to_string(),
            channel_type: ChannelType::Public,
            display_name: None,
            description: None,
            content_rating: Default::default(),
            moderation: ModerationPolicy { admins: vec![], rules: None },
            encryption_enabled: None,
            history_visibility: None,
            id_derivation_ts: None,
        };
        // Positional array encoding, matching sdk-rust's wire form — NOT
        // `to_vec_named` (which every OTHER helper in this module uses).
        let payload_bytes = rmp_serde::to_vec(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            &sk,
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
            author: creator.clone(),
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        let raw = rmp_serde::to_vec_named(&envelope).unwrap();

        let result = r.process_message(&raw);
        assert!(matches!(result, RouteResult::Accepted { .. }), "got {:?}", result);

        let key = schema::encode_channel_meta_key(
            channel_id,
            MessageType::ChannelCreate as u8,
            timestamp,
            &msg_id,
        );
        assert!(
            r.storage.exists_cf(schema::cf::CHANNEL_META_MSGS, &key).unwrap_or(false),
            "an array-encoded ChannelCreate must still be indexed into \
             CHANNEL_META_MSGS so a backfilling peer can be served this \
             channel's metadata"
        );
    }

    // --- Security fix (2026-10-06): private channel_id identity-binding,
    // absence policy (MessageRouter::require_private_id_derivation) ---

    #[test]
    fn live_private_create_without_derivation_is_rejected() {
        // !is_sync: Step 5's timestamp-freshness check already ran, so a
        // "legacy" LIVE create without a derivation is impossible by
        // construction — always reject, no cutover window.
        let (r, _d) = router();
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);

        let payload = ChannelCreatePayload {
            channel_id: (1u64 << 32) + 9001,
            slug: "test-channel".to_string(),
            channel_type: ChannelType::Private,
            display_name: None,
            description: None,
            content_rating: Default::default(),
            moderation: ModerationPolicy { admins: vec![], rules: None },
            encryption_enabled: None,
            history_visibility: None,
            id_derivation_ts: None, // absent — the vulnerable shape
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let timestamp = now_ms();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            &sk,
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
            author: creator,
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        let raw = rmp_serde::to_vec_named(&envelope).unwrap();
        match r.process_message(&raw) {
            RouteResult::Rejected(_) => {}
            other => panic!("expected Rejected (live create needs a derivation), got {:?}", other),
        }
    }

    #[test]
    fn synced_private_create_first_sight_without_derivation_is_rejected() {
        // is_sync + no local CHANNELS row (first-ever encounter): exactly
        // the federate_channel first-sight-trust case this fix closes —
        // fail closed.
        let (r, _d) = router();
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);

        let payload = ChannelCreatePayload {
            channel_id: (1u64 << 32) + 9002,
            slug: "test-channel".to_string(),
            channel_type: ChannelType::Private,
            display_name: None,
            description: None,
            content_rating: Default::default(),
            moderation: ModerationPolicy { admins: vec![], rules: None },
            encryption_enabled: None,
            history_visibility: None,
            id_derivation_ts: None,
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let timestamp = now_ms();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            &sk,
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
            author: creator,
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        let raw = rmp_serde::to_vec_named(&envelope).unwrap();
        match r.process_synced_message(&raw) {
            RouteResult::Rejected(_) => {}
            other => panic!("expected Rejected (first sight needs a derivation), got {:?}", other),
        }
    }

    #[test]
    fn synced_private_create_for_an_already_known_channel_accepts_absent_derivation() {
        // is_sync + a local CHANNELS row already exists: the pure-merge
        // path, already creator-gated — legacy backfill/replay for a
        // channel this node ALREADY knows must keep working even without
        // a derivation.
        let (r, _d) = router();
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);
        let channel_id = (1u64 << 32) + 9003;
        make_channel(&r, channel_id, &creator);

        let payload = ChannelCreatePayload {
            channel_id,
            slug: "test-channel".to_string(),
            channel_type: ChannelType::Private,
            display_name: None,
            description: None,
            content_rating: Default::default(),
            moderation: ModerationPolicy { admins: vec![], rules: None },
            encryption_enabled: None,
            history_visibility: None,
            id_derivation_ts: None,
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let timestamp = now_ms();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            &sk,
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
            author: creator,
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        let raw = rmp_serde::to_vec_named(&envelope).unwrap();
        assert!(matches!(r.process_synced_message(&raw), RouteResult::Accepted { .. }));
    }

    /// Security-audit finding (2026-10-06, round 3): the test above proves
    /// a non-creator's absent-derivation create is ACCEPTED on the synced+
    /// existing-row path (by design — legacy backfill must keep working).
    /// But acceptance alone used to also index the envelope into
    /// `CHANNEL_META_MSGS` unconditionally, handing an attacker who merely
    /// knows a private channel's id a standing row they could backdate to
    /// win `channel_bootstrap_envelopes`' selection — the DoS this test
    /// guards against. The row must be accepted (merge logic drops it)
    /// but must NOT be indexed at all.
    #[test]
    fn synced_non_creator_create_for_a_known_channel_is_accepted_but_not_indexed() {
        let (r, _d) = router();
        let creator_sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&creator_sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);
        let channel_id = (1u64 << 32) + 9004;
        make_channel(&r, channel_id, &creator);

        let attacker_sk = crypto::generate_keypair();
        let attacker = crypto::pubkey_to_address(&attacker_sk.verifying_key()).unwrap();
        register_user(&r, &attacker, 1_000);

        let payload = ChannelCreatePayload {
            channel_id,
            slug: "test-channel".to_string(),
            channel_type: ChannelType::Private,
            display_name: None,
            description: None,
            content_rating: Default::default(),
            moderation: ModerationPolicy { admins: vec![], rules: None },
            encryption_enabled: None,
            history_visibility: None,
            id_derivation_ts: None,
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let timestamp = now_ms();
        let author_pubkey: [u8; 32] = attacker_sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            &attacker_sk,
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
            author: attacker,
            timestamp,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        let raw = rmp_serde::to_vec_named(&envelope).unwrap();

        assert!(matches!(r.process_synced_message(&raw), RouteResult::Accepted { .. }));

        let key = schema::encode_channel_meta_key(
            channel_id,
            MessageType::ChannelCreate as u8,
            timestamp,
            &msg_id,
        );
        assert!(
            !r.storage.exists_cf(schema::cf::CHANNEL_META_MSGS, &key).unwrap_or(true),
            "a non-creator's ChannelCreate for an already-known channel must be accepted (merge \
             logic drops it) but never indexed into CHANNEL_META_MSGS — indexing it hands an \
             attacker who merely knows the channel_id a standing row to backdate and win \
             channel_bootstrap_envelopes' selection"
        );
    }

    fn router_with_flag(require_private_id_derivation: bool) -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        let r = MessageRouter::new(
            storage,
            identity,
            None,
            "testnet".to_string(),
            usize::MAX,
            std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()),
            crate::config::RateLimitsConfig::default(),
        )
        .with_channel_verify_config(crate::config::ChannelVerifyConfig {
            require_private_id_derivation,
            ..Default::default()
        });
        (r, dir)
    }

    fn unsigned_private_create_envelope(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        channel_id: u64,
        id_derivation_ts: Option<u64>,
        timestamp: u64,
    ) -> Vec<u8> {
        let payload = ChannelCreatePayload {
            channel_id,
            slug: "test-channel".to_string(),
            channel_type: ChannelType::Private,
            display_name: None,
            description: None,
            content_rating: Default::default(),
            moderation: ModerationPolicy { admins: vec![], rules: None },
            encryption_enabled: None,
            history_visibility: None,
            id_derivation_ts,
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            &sk,
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

    /// Security-audit regression (2026-10-06): the config flag check used
    /// to run BEFORE the `!is_sync` guard, so `require_private_id_
    /// derivation = false` also accepted an absent derivation on a LIVE
    /// create — silently reopening the full original vulnerability on
    /// live traffic. The flag must NEVER soften the live-create
    /// requirement, only the synced/first-sight one.
    #[test]
    fn require_private_id_derivation_false_still_rejects_a_live_create_missing_derivation() {
        let (r, _d) = router_with_flag(false);
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);
        let raw = unsigned_private_create_envelope(&sk, &creator, (1u64 << 32) + 9005, None, now_ms());
        match r.process_message(&raw) {
            RouteResult::Rejected(_) => {}
            other => panic!(
                "the escape hatch must never accept a LIVE create missing its derivation, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn require_private_id_derivation_false_accepts_synced_first_sight_absence() {
        // The escape hatch's actual, documented scope: only the
        // synced/first-sight branch (an operator unblocking a legacy
        // pre-upgrade channel that needs to federate onto a fresh node).
        let (r, _d) = router_with_flag(false);
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);
        let raw = unsigned_private_create_envelope(&sk, &creator, (1u64 << 32) + 9006, None, now_ms());
        assert!(matches!(r.process_synced_message(&raw), RouteResult::Accepted { .. }));
    }

    #[test]
    fn require_private_id_derivation_false_still_rejects_a_present_mismatched_derivation() {
        // The flag only ever softens ABSENCE policy — a PRESENT derivation
        // is unconditionally verified (`validate_channel_create` has no
        // access to this flag at all), flag or no flag.
        let (r, _d) = router_with_flag(false);
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);
        // A channel_id that does NOT match Keccak-256(creator+slug+ts) for
        // this ts — i.e. a present, wrong derivation.
        let raw = unsigned_private_create_envelope(
            &sk,
            &creator,
            (1u64 << 32) + 9007,
            Some(1_700_000_000_000),
            now_ms(),
        );
        match r.process_synced_message(&raw) {
            RouteResult::Rejected(_) => {}
            other => panic!("a present-but-mismatched derivation must be rejected regardless of the flag, got {:?}", other),
        }
    }

    /// Security fix (2026-10-06): the hash must use the resolved WALLET
    /// address, never the signing DEVICE key — a delegated device's
    /// `ChannelCreate` must verify against its wallet.
    #[test]
    fn device_delegated_create_verifies_against_the_wallet_address_not_the_device_key() {
        let (r, _d) = router();
        let wallet_sk = crypto::generate_keypair();
        let wallet = crypto::pubkey_to_address(&wallet_sk.verifying_key()).unwrap();
        register_user(&r, &wallet, 1_000);

        let device_sk = crypto::generate_keypair();
        let device_address = crypto::device_pubkey_to_address(&device_sk.verifying_key()).unwrap();
        r.identity
            .register_device(&crate::storage::rocks::DeviceClaim {
                device_address: device_address.clone(),
                wallet_address: wallet.clone(),
                device_pubkey_hex: hex::encode(device_sk.verifying_key().to_bytes()),
                wallet_signature: "test".to_string(),
                registered_at: 1_000,
            })
            .unwrap();

        let slug = "test-channel";
        let ts = now_ms();
        const JS_SAFE_INTEGER_MODULUS: u64 = (1u64 << 53) - 1;
        const FLOOR: u64 = 1 << 32;
        let derive = |addr: &str, t: u64| -> u64 {
            let preimage = format!("{addr}{slug}{t}");
            let hash = crypto::keccak256(preimage.as_bytes());
            let raw = u64::from_be_bytes([
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            ]);
            raw % JS_SAFE_INTEGER_MODULUS
        };
        // Hash over the WALLET address (what a compliant client does) —
        // must be accepted even though the envelope is signed by the device key.
        let mut ts_wallet = ts;
        let channel_id = loop {
            let id = derive(&wallet, ts_wallet);
            if id > FLOOR {
                break id;
            }
            ts_wallet += 1;
        };
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
            id_derivation_ts: Some(ts_wallet),
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let device_pubkey: [u8; 32] = device_sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &device_pubkey, &payload_bytes, ts_wallet);
        let signature = signing::sign_ogmara_message(
            &device_sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ChannelCreate as u8,
            &msg_id,
            ts_wallet,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChannelCreate,
            msg_id,
            author: device_address.clone(), // envelope signed by the DEVICE key
            timestamp: ts_wallet,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        let raw = rmp_serde::to_vec_named(&envelope).unwrap();
        let result = r.process_message(&raw);
        assert!(
            matches!(result, RouteResult::Accepted { .. }),
            "hash over the resolved WALLET address must verify even though the envelope is \
             device-key-signed, got {:?}",
            result
        );
    }

    #[test]
    fn device_delegated_create_hashed_over_the_device_key_is_rejected() {
        // Same setup as above, but the hash is computed over the DEVICE
        // address instead of the wallet — a buggy (or malicious) client
        // doing this must be rejected, not silently accepted.
        let (r, _d) = router();
        let wallet_sk = crypto::generate_keypair();
        let wallet = crypto::pubkey_to_address(&wallet_sk.verifying_key()).unwrap();
        register_user(&r, &wallet, 1_000);

        let device_sk = crypto::generate_keypair();
        let device_address = crypto::device_pubkey_to_address(&device_sk.verifying_key()).unwrap();
        r.identity
            .register_device(&crate::storage::rocks::DeviceClaim {
                device_address: device_address.clone(),
                wallet_address: wallet.clone(),
                device_pubkey_hex: hex::encode(device_sk.verifying_key().to_bytes()),
                wallet_signature: "test".to_string(),
                registered_at: 1_000,
            })
            .unwrap();

        let slug = "test-channel";
        const JS_SAFE_INTEGER_MODULUS: u64 = (1u64 << 53) - 1;
        const FLOOR: u64 = 1 << 32;
        let derive = |addr: &str, t: u64| -> u64 {
            let preimage = format!("{addr}{slug}{t}");
            let hash = crypto::keccak256(preimage.as_bytes());
            let raw = u64::from_be_bytes([
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
            ]);
            raw % JS_SAFE_INTEGER_MODULUS
        };
        let mut ts_device = now_ms();
        let channel_id = loop {
            let id = derive(&device_address, ts_device);
            if id > FLOOR {
                break id;
            }
            ts_device += 1;
        };
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
            id_derivation_ts: Some(ts_device),
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let device_pubkey: [u8; 32] = device_sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &device_pubkey, &payload_bytes, ts_device);
        let signature = signing::sign_ogmara_message(
            &device_sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ChannelCreate as u8,
            &msg_id,
            ts_device,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChannelCreate,
            msg_id,
            author: device_address,
            timestamp: ts_device,
            lamport_ts: 0,
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        let raw = rmp_serde::to_vec_named(&envelope).unwrap();
        match r.process_message(&raw) {
            RouteResult::Rejected(_) => {}
            other => panic!(
                "a hash computed over the device address (not the resolved wallet) must be \
                 rejected, got {:?}",
                other
            ),
        }
    }
}

#[cfg(test)]
mod channel_create_encryption_merge_tests {
    //! Reproduces a live bug report (2026-09-14): a public channel created via
    //! desktop's two-phase flow (on-chain SC tx first, L2 ChannelCreate
    //! envelope published only after chain confirmation) ended up with NO
    //! `encryption_enabled` field at all in its stored CHANNELS record, even
    //! though the creating client sent `encryptionEnabled: true` and its own
    //! messages into the channel were genuinely v2-encrypted (`enc_content`
    //! present). Consequence: any OTHER reader of the channel record —
    //! ogmara-bot's `describeChannel`, or another wallet's client, which uses
    //! this SAME field to decide `encrypt-on-send` (desktop
    //! `ChatView.tsx:507`) — would treat the channel as legacy-plaintext and
    //! could itself send an UNENCRYPTED message into it.
    //!
    //! The suspected mechanism: the chain scanner can create a bare
    //! `ChannelRecord` skeleton (no `encryption_enabled` key at all) for the
    //! channel BEFORE the creator's L2 `ChannelCreate` envelope arrives and
    //! merges in the real encryption flags via `obj.entry("encryption_enabled")
    //! .or_insert(...)` (router.rs ~2419-2426) — but that merge only runs when
    //! `is_creator` (comparing the skeleton's stored `creator` against the
    //! envelope's `resolved_author`) is true.
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

    fn register_user(r: &MessageRouter, address: &str, registered_at: u64) {
        let rec = serde_json::json!({ "address": address, "registered_at": registered_at });
        r.storage.put_cf(schema::cf::USERS, address.as_bytes(), rec.to_string().as_bytes()).unwrap();
    }

    /// Mirrors the chain scanner's "first time we've seen this channel" write
    /// (scanner.rs ~599-612): the plain `ChannelRecord` struct, which has no
    /// `encryption_enabled` field to serialize in the first place.
    fn make_chain_scanner_skeleton(r: &MessageRouter, channel_id: u64, creator: &str) {
        let record = crate::chain::types::ChannelRecord {
            channel_id,
            slug: "testtest123".to_string(),
            creator: creator.to_string(),
            channel_type: 0,
            created_at: 1_000,
            display_name: None,
            description: None,
            member_count: 0,
        };
        r.storage
            .put_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes(), &serde_json::to_vec(&record).unwrap())
            .unwrap();
    }

    fn signed_public_create_envelope(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        channel_id: u64,
        timestamp: u64,
    ) -> Vec<u8> {
        let payload = ChannelCreatePayload {
            channel_id,
            slug: "testtest123".to_string(),
            channel_type: ChannelType::Public,
            display_name: None,
            description: None,
            content_rating: Default::default(),
            moderation: ModerationPolicy { admins: vec![], rules: None },
            // What desktop actually sends (ChannelCreateView.tsx: `encryptionEnabled: true`).
            encryption_enabled: Some(true),
            history_visibility: None,
            id_derivation_ts: None,
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk, "testnet", crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ChannelCreate as u8, &msg_id, timestamp, &payload_bytes,
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
    fn skeleton_then_real_create_by_the_same_creator_merges_encryption_enabled() {
        let (r, _d) = router();
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);
        let cid = 5001u64;

        // Chain scanner sees the on-chain event FIRST (plausible: the client
        // waits for on-chain confirmation before publishing the L2 envelope,
        // so the scanner has a head start).
        make_chain_scanner_skeleton(&r, cid, &creator);
        assert!(
            !r.storage.get_cf(schema::cf::CHANNELS, &cid.to_be_bytes()).unwrap().unwrap()
                .windows(19).any(|w| w == b"encryption_enabled"),
            "sanity check: the bare skeleton must not already have the key"
        );

        let raw = signed_public_create_envelope(&sk, &creator, cid, now_ms());
        let result = r.process_message(&raw);
        assert!(matches!(result, RouteResult::Accepted { .. }), "got {:?}", result);

        let stored = r.storage.get_cf(schema::cf::CHANNELS, &cid.to_be_bytes()).unwrap().unwrap();
        let meta: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(
            meta.get("encryption_enabled"), Some(&serde_json::json!(true)),
            "the creator's own ChannelCreate must merge encryption_enabled into a pre-existing \
             chain-scanner skeleton, not leave it permanently unset. Full stored record: {meta}"
        );
    }

    #[test]
    fn real_create_arriving_first_then_a_late_chain_scan_does_not_clobber_encryption_enabled() {
        // The reverse ordering: the L2 envelope wins the race and creates the
        // full record correctly; a LATER chain-scan of the same on-chain
        // event must not downgrade it back to unencrypted.
        let (r, _d) = router();
        let sk = crypto::generate_keypair();
        let creator = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &creator, 1_000);
        let cid = 5002u64;

        let raw = signed_public_create_envelope(&sk, &creator, cid, now_ms());
        assert!(matches!(r.process_message(&raw), RouteResult::Accepted { .. }));
        let before = r.storage.get_cf(schema::cf::CHANNELS, &cid.to_be_bytes()).unwrap().unwrap();
        let before: serde_json::Value = serde_json::from_slice(&before).unwrap();
        assert_eq!(before.get("encryption_enabled"), Some(&serde_json::json!(true)));

        // Simulate the chain scanner's "already exists" merge branch directly
        // (scanner.rs ~569-589): it overwrites channel_id/slug/creator/
        // channel_type/created_at unconditionally and only `or_insert`s
        // display_name/description/member_count — it must never touch
        // encryption_enabled at all, in either direction.
        let existing = r.storage.get_cf(schema::cf::CHANNELS, &cid.to_be_bytes()).unwrap().unwrap();
        let mut meta: serde_json::Value = serde_json::from_slice(&existing).unwrap();
        if let Some(obj) = meta.as_object_mut() {
            obj.insert("channel_id".into(), serde_json::json!(cid));
            obj.insert("slug".into(), serde_json::json!("testtest123"));
            obj.insert("creator".into(), serde_json::json!(creator));
            obj.insert("channel_type".into(), serde_json::json!(0u8));
            obj.insert("created_at".into(), serde_json::json!(1_000u64));
            obj.entry("display_name").or_insert(serde_json::Value::Null);
            obj.entry("description").or_insert(serde_json::Value::Null);
            obj.entry("member_count").or_insert(serde_json::json!(0));
        }
        r.storage.put_cf(schema::cf::CHANNELS, &cid.to_be_bytes(), &serde_json::to_vec(&meta).unwrap()).unwrap();

        let after = r.storage.get_cf(schema::cf::CHANNELS, &cid.to_be_bytes()).unwrap().unwrap();
        let after: serde_json::Value = serde_json::from_slice(&after).unwrap();
        assert_eq!(
            after.get("encryption_enabled"), Some(&serde_json::json!(true)),
            "a later chain-scan merge must not clobber an already-correct encryption_enabled"
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
            buttons: vec![],
            via_button: false,
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
            buttons: vec![],
            via_button: false,
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
                    buttons: None,
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
mod chat_edit_encrypted_shape_authorization_tests {
    //! Write-time regression guard for the encrypted-`ChatEdit` feature
    //! (`authorize_edit_delete`'s step 6): before this check existed, an
    //! ORDINARY plaintext `ChatEdit` against an already-encrypted channel
    //! message was accepted, stored, and gossiped — then permanently blanked
    //! by `project_edited_payload`'s (api/routes.rs) shape-mismatch fail-safe
    //! the moment anyone tried to read it. Every shipped client today only
    //! ever sends a plaintext `ChatEdit` (no SDK can build an encrypted one
    //! yet), so without this write-time rejection, deploying the read-side
    //! encrypted-edit feature alone would have turned "editing any message in
    //! any encrypted channel" — the default for new Public/ReadPublic/Private
    //! channels — into silent, permanent data loss. These tests exercise the
    //! REAL entry point (`process_message`, full signature verification +
    //! authorization), not `authorize_edit_delete` in isolation.
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

    fn register_user(r: &MessageRouter, address: &str, registered_at: u64) {
        let rec = serde_json::json!({ "address": address, "registered_at": registered_at });
        r.storage
            .put_cf(schema::cf::USERS, address.as_bytes(), rec.to_string().as_bytes())
            .unwrap();
    }

    /// Store a genuine ChatMessage directly in MESSAGES — plaintext if
    /// `enc` is `None`, encrypted otherwise. Bypasses full envelope signing
    /// (mirrors `edit_delete_index_tests::store_chat_message`; irrelevant to
    /// what `authorize_edit_delete` reads).
    fn store_chat_message(
        r: &MessageRouter,
        author: &str,
        channel_id: u64,
        msg_id: [u8; 32],
        timestamp: u64,
        enc: Option<(Vec<u8>, [u8; 24], u64)>,
    ) {
        let (content, enc_content, enc_nonce, key_epoch) = match enc {
            Some((ct, nonce, epoch)) => ("".to_string(), Some(ct), Some(nonce), Some(epoch)),
            None => ("hello".to_string(), None, None, None),
        };
        let payload = ChatMessagePayload {
            channel_id,
            content,
            content_rating: Default::default(),
            reply_to: None,
            mentions: vec![],
            attachments: vec![],
            enc_content,
            enc_nonce,
            key_epoch,
            buttons: vec![],
            via_button: false,
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

    /// Build a fully signed `ChatEdit` envelope, plaintext or encrypted
    /// depending on `enc`.
    fn signed_chat_edit(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        target_id: [u8; 32],
        channel_id: u64,
        timestamp: u64,
        enc: Option<(Vec<u8>, [u8; 24], u64)>,
    ) -> Vec<u8> {
        let (content, enc_content, enc_nonce, key_epoch) = match enc {
            Some((ct, nonce, epoch)) => ("".to_string(), Some(ct), Some(nonce), Some(epoch)),
            None => ("edited".to_string(), None, None, None),
        };
        let payload = EditPayload {
            target_id,
            channel_id: Some(channel_id),
            content,
            edited_at: timestamp,
            title: None,
            tags: None,
            attachments: None,
            buttons: None,
            enc_content,
            enc_nonce,
            key_epoch,
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ChatEdit as u8,
            &msg_id,
            timestamp,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChatEdit,
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
    fn plaintext_edit_against_plaintext_original_is_accepted() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let channel_id = 42u64;
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        store_chat_message(&r, &author, channel_id, original_id, original_ts, None);

        let edit_raw = signed_chat_edit(&sk, &author, original_id, channel_id, original_ts + 1, None);
        assert!(matches!(r.process_message(&edit_raw), RouteResult::Accepted { .. }));
    }

    #[test]
    fn encrypted_edit_against_encrypted_original_is_accepted() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let channel_id = 42u64;
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        store_chat_message(
            &r, &author, channel_id, original_id, original_ts,
            Some((vec![9, 9, 9], [1u8; 24], 1)),
        );

        let edit_raw = signed_chat_edit(
            &sk, &author, original_id, channel_id, original_ts + 1,
            Some((vec![7, 7, 7], [2u8; 24], 1)),
        );
        assert!(matches!(r.process_message(&edit_raw), RouteResult::Accepted { .. }));
    }

    /// THE regression this module exists to guard: before the write-time
    /// check, this exact sequence — a normal plaintext edit (all that any
    /// shipped client can build) against an encrypted original — was
    /// ACCEPTED and stored, then permanently blanked the message the next
    /// time anyone read it.
    #[test]
    fn plaintext_edit_against_encrypted_original_is_rejected() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let channel_id = 42u64;
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        store_chat_message(
            &r, &author, channel_id, original_id, original_ts,
            Some((vec![9, 9, 9], [1u8; 24], 1)),
        );

        let edit_raw = signed_chat_edit(&sk, &author, original_id, channel_id, original_ts + 1, None);
        assert!(matches!(r.process_message(&edit_raw), RouteResult::Rejected(_)));

        // The original message must be completely untouched by the rejected
        // edit attempt — still readable, still encrypted, unedited.
        let stored = r.storage.get_cf(schema::cf::MESSAGES, &original_id).unwrap().unwrap();
        let env: Envelope = rmp_serde::from_slice(&stored).unwrap();
        let p: ChatMessagePayload = rmp_serde::from_slice(&env.payload).unwrap();
        assert_eq!(p.enc_content, Some(vec![9, 9, 9]));
    }

    #[test]
    fn encrypted_edit_against_plaintext_original_is_rejected() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let channel_id = 42u64;
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        store_chat_message(&r, &author, channel_id, original_id, original_ts, None);

        let edit_raw = signed_chat_edit(
            &sk, &author, original_id, channel_id, original_ts + 1,
            Some((vec![7, 7, 7], [2u8; 24], 1)),
        );
        assert!(matches!(r.process_message(&edit_raw), RouteResult::Rejected(_)));
    }

    /// AEAD hygiene (security audit NOTE): reusing the original's exact
    /// nonce under an unchanged key_epoch would encrypt the edit under the
    /// same (key, nonce) pair as the original ciphertext — a confidentiality
    /// break for XChaCha20-Poly1305. Rejected even though the node never
    /// generates nonces itself; a client bug/malice is the only way this
    /// could happen, and storing it would gossip a provably-broken
    /// ciphertext to every channel member.
    #[test]
    fn encrypted_edit_reusing_original_nonce_at_same_epoch_is_rejected() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let channel_id = 42u64;
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        let shared_nonce = [5u8; 24];
        store_chat_message(
            &r, &author, channel_id, original_id, original_ts,
            Some((vec![9, 9, 9], shared_nonce, 1)),
        );

        let edit_raw = signed_chat_edit(
            &sk, &author, original_id, channel_id, original_ts + 1,
            Some((vec![7, 7, 7], shared_nonce, 1)),
        );
        assert!(matches!(r.process_message(&edit_raw), RouteResult::Rejected(_)));

        let stored = r.storage.get_cf(schema::cf::MESSAGES, &original_id).unwrap().unwrap();
        let env: Envelope = rmp_serde::from_slice(&stored).unwrap();
        let p: ChatMessagePayload = rmp_serde::from_slice(&env.payload).unwrap();
        assert_eq!(p.enc_content, Some(vec![9, 9, 9]), "rejected edit must not have touched the original");
    }

    /// Same physical nonce bytes are safe to reuse across a DIFFERENT
    /// key_epoch — a key rotation derives a new key, so (new key, reused
    /// nonce) is not the same pair as (old key, original nonce). Confirms
    /// the check is scoped to "same epoch", not "ever reused this value".
    #[test]
    fn encrypted_edit_reusing_nonce_bytes_under_a_bumped_epoch_is_accepted() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let channel_id = 42u64;
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        let shared_nonce = [5u8; 24];
        store_chat_message(
            &r, &author, channel_id, original_id, original_ts,
            Some((vec![9, 9, 9], shared_nonce, 1)),
        );

        let edit_raw = signed_chat_edit(
            &sk, &author, original_id, channel_id, original_ts + 1,
            Some((vec![7, 7, 7], shared_nonce, 2)),
        );
        assert!(matches!(r.process_message(&edit_raw), RouteResult::Accepted { .. }));
    }

    /// Regression guard for a bug in an EARLIER version of this hardening:
    /// once any encrypted edit exists, the check must still catch a LATER
    /// edit reusing the ORIGINAL's nonce (not just the latest edit's) — an
    /// earlier version compared only against the current latest edit,
    /// replacing rather than unioning the comparison set, so this exact
    /// sequence was wrongly accepted.
    #[test]
    fn encrypted_edit_reusing_the_original_nonce_is_rejected_even_after_an_intervening_edit() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let channel_id = 42u64;
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        let original_nonce = [5u8; 24];
        store_chat_message(
            &r, &author, channel_id, original_id, original_ts,
            Some((vec![9, 9, 9], original_nonce, 1)),
        );

        // edit1: different nonce AND different epoch — accepted, becomes the
        // latest edit.
        let edit1_raw = signed_chat_edit(
            &sk, &author, original_id, channel_id, original_ts + 1,
            Some((vec![7, 7, 7], [6u8; 24], 2)),
        );
        assert!(matches!(r.process_message(&edit1_raw), RouteResult::Accepted { .. }));

        // edit2: reuses the ORIGINAL's exact (nonce, epoch) — must still be
        // caught even though it differs from edit1's (the current latest
        // edit's) nonce and epoch.
        let edit2_raw = signed_chat_edit(
            &sk, &author, original_id, channel_id, original_ts + 2,
            Some((vec![3, 3, 3], original_nonce, 1)),
        );
        assert!(matches!(r.process_message(&edit2_raw), RouteResult::Rejected(_)));
    }

    /// Exercises the `get_edit_history` scan branch specifically (as opposed
    /// to the pre-loop check against the ORIGINAL): a THIRD edit reuses the
    /// FIRST edit's nonce+epoch — a collision the loop must catch even
    /// though neither the original nor the (by-then) latest edit shares
    /// that nonce. Without the loop (i.e. comparing only against the
    /// current latest edit, the bug two rounds of audit found and fixed),
    /// this would be wrongly accepted.
    #[test]
    fn encrypted_edit_reusing_a_non_latest_non_original_prior_edits_nonce_is_rejected() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let channel_id = 42u64;
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        store_chat_message(
            &r, &author, channel_id, original_id, original_ts,
            Some((vec![9, 9, 9], [1u8; 24], 1)),
        );

        // edit1: nonce N1, epoch 2 — accepted.
        let n1 = [6u8; 24];
        let edit1_raw = signed_chat_edit(
            &sk, &author, original_id, channel_id, original_ts + 1,
            Some((vec![7, 7, 7], n1, 2)),
        );
        assert!(matches!(r.process_message(&edit1_raw), RouteResult::Accepted { .. }));

        // edit2: nonce N2 (fresh), epoch 3 — accepted, becomes the new
        // latest edit. edit1 is now neither the original nor the latest.
        let edit2_raw = signed_chat_edit(
            &sk, &author, original_id, channel_id, original_ts + 2,
            Some((vec![8, 8, 8], [7u8; 24], 3)),
        );
        assert!(matches!(r.process_message(&edit2_raw), RouteResult::Accepted { .. }));

        // edit3: reuses edit1's (N1, epoch 2) — must be caught by the
        // `get_edit_history` scan, since it matches neither the original
        // nor edit2 (the current latest edit).
        let edit3_raw = signed_chat_edit(
            &sk, &author, original_id, channel_id, original_ts + 3,
            Some((vec![2, 2, 2], n1, 2)),
        );
        let result = r.process_message(&edit3_raw);
        assert!(
            matches!(&result, RouteResult::Rejected(msg) if msg.contains("reuse a nonce")),
            "expected a nonce-reuse rejection, got {result:?}",
        );
    }

    /// Regression guard: `DirectMessageEdit`/`NewsEdit` must be entirely
    /// unaffected by the new check (`edit_chat_shape` is `None` for
    /// both, so the new branch in `authorize_edit_delete` is skipped) — a
    /// DM edit is ALWAYS encrypted by a different mechanism entirely
    /// (already enforced by `validate_dm_edit`, untouched by this change).
    #[test]
    fn dm_edit_is_unaffected_by_the_new_chat_specific_check() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let recipient = "klv1recipient00000000000000000000000000000000000000000000000000";
        register_user(&r, &author, 1_000);
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        let payload = DirectMessagePayload {
            recipient: recipient.to_string(),
            conversation_id: crate::crypto::compute_conversation_id(&author, recipient),
            content: vec![1, 2, 3],
            nonce: [0u8; 24],
            key_epoch: 1,
            reply_to: None,
            attachments: vec![],
        };
        let orig_env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::DirectMessage,
            msg_id: original_id,
            author: author.clone(),
            timestamp: original_ts,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        r.storage
            .put_cf(schema::cf::MESSAGES, &original_id, &rmp_serde::to_vec_named(&orig_env).unwrap())
            .unwrap();

        let edit_payload_bytes = rmp_serde::to_vec_named(&EditPayload {
            target_id: original_id,
            channel_id: None,
            content: "".to_string(),
            edited_at: original_ts + 1,
            title: None,
            tags: None,
            attachments: None,
            buttons: None,
            enc_content: Some(vec![7, 7, 7]),
            enc_nonce: Some([2u8; 24]),
            key_epoch: Some(1),
        })
        .unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let edit_ts = original_ts + 1;
        let edit_msg_id =
            crypto::compute_msg_id("testnet", &author_pubkey, &edit_payload_bytes, edit_ts);
        let signature = signing::sign_ogmara_message(
            &sk, "testnet", crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::DirectMessageEdit as u8, &edit_msg_id, edit_ts, &edit_payload_bytes,
        );
        let edit_env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::DirectMessageEdit,
            msg_id: edit_msg_id,
            author,
            timestamp: edit_ts,
            lamport_ts: 0,
            payload: edit_payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: vec![],
        };
        let edit_raw = rmp_serde::to_vec_named(&edit_env).unwrap();
        // Accepted (or rejected for some OTHER, unrelated DM-specific reason
        // — e.g. recipient-cap/rate-limit plumbing this minimal harness
        // doesn't set up) — the only thing this test guards is that it is
        // never rejected by the NEW chat-shape check, which would show up as
        // a `Rejected` whose message names ChatEdit-specific text. Assert on
        // the error text directly to distinguish "unaffected" from
        // "coincidentally also rejected, for a different reason" — the
        // former is fine, the latter would defeat the test.
        if let RouteResult::Rejected(msg) = r.process_message(&edit_raw) {
            assert!(
                !msg.contains("plaintext edit") && !msg.contains("encrypted edit"),
                "DM edit was rejected by the new ChatEdit-specific shape check: {msg}",
            );
        }
    }
}

#[cfg(test)]
mod edit_delete_type_correspondence_tests {
    //! Security-audit HIGH finding, PoC-verified: `EditPayload`/`DeletePayload`
    //! carry `target_id` with no type tag, so nothing stopped a `NewsEdit`
    //! from pointing its `target_id` at a `ChatMessage`. The VALIDATOR
    //! dispatch is keyed on the EDIT's own `msg_type` (`NewsEdit` →
    //! `validate_news_edit`, which has no `enc_content` concept and never
    //! inspects it), while the PROJECTION dispatch in
    //! `project_edited_payload` (api/routes.rs) is keyed on the TARGET's
    //! ACTUAL stored type — so a type-confused `NewsEdit` sailed past
    //! `validate_news_edit`, past the ChatEdit-only shape check added
    //! earlier in this same change (gated on `envelope.msg_type ==
    //! MessageType::ChatEdit`, so it never even looks at a `NewsEdit`), and
    //! landed in `ChatMessage`'s projection branch — bypassing
    //! `validate_chat_edit`'s `MAX_CHAT_CIPHERTEXT` cap and `key_epoch >= 1`
    //! floor entirely (PoC: 20,000-byte ciphertext, `key_epoch: 0`, and
    //! plaintext `content` coexisting with `enc_content` — a shape every
    //! relevant validator is supposed to forbid). `authorize_edit_delete`'s
    //! new step 3 closes the whole class by requiring the edit/delete's own
    //! type to match what the target is actually stored as, checked before
    //! anything type-specific runs (including authorship).
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

    fn register_user(r: &MessageRouter, address: &str, registered_at: u64) {
        let rec = serde_json::json!({ "address": address, "registered_at": registered_at });
        r.storage
            .put_cf(schema::cf::USERS, address.as_bytes(), rec.to_string().as_bytes())
            .unwrap();
    }

    fn store_message(r: &MessageRouter, msg_type: MessageType, author: &str, msg_id: [u8; 32], timestamp: u64, payload: Vec<u8>) {
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type,
            msg_id,
            author: author.to_string(),
            timestamp,
            lamport_ts: 0,
            payload,
            signature: vec![],
            relay_path: vec![],
        };
        r.storage
            .put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&envelope).unwrap())
            .unwrap();
    }

    fn encrypted_chat_message_payload() -> Vec<u8> {
        rmp_serde::to_vec_named(&ChatMessagePayload {
            channel_id: 42,
            content: String::new(),
            content_rating: Default::default(),
            reply_to: None,
            mentions: vec![],
            attachments: vec![],
            enc_content: Some(vec![9, 9, 9]),
            enc_nonce: Some([1u8; 24]),
            key_epoch: Some(1),
            buttons: vec![],
            via_button: false,
        })
        .unwrap()
    }

    fn news_post_payload() -> Vec<u8> {
        rmp_serde::to_vec_named(&NewsPostPayload {
            title: "headline".to_string(),
            content: "body".to_string(),
            content_rating: Default::default(),
            tags: vec![],
            attachments: vec![],
            visibility: Default::default(),
        })
        .unwrap()
    }

    /// Build a fully signed envelope of `msg_type` carrying `payload_bytes`.
    fn signed(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        msg_type: MessageType,
        timestamp: u64,
        payload_bytes: Vec<u8>,
    ) -> Vec<u8> {
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk, "testnet", crate::messages::envelope::PROTOCOL_VERSION,
            msg_type as u8, &msg_id, timestamp, &payload_bytes,
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

    /// The audit's own PoC shape: a `NewsEdit` whose `target_id` points at
    /// an encrypted `ChatMessage`, carrying an oversize ciphertext and the
    /// forbidden `key_epoch: 0` — none of which `validate_news_edit` checks.
    /// Before the fix, this reached and corrupted the `ChatMessage`.
    #[test]
    fn news_edit_cannot_target_a_chat_message() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        store_message(&r, MessageType::ChatMessage, &author, original_id, original_ts, encrypted_chat_message_payload());

        let edit_payload = EditPayload {
            target_id: original_id,
            channel_id: None,
            content: "smuggled plaintext, oversize ciphertext riding along".to_string(),
            edited_at: original_ts + 1,
            title: None,
            tags: None,
            attachments: None,
            buttons: None,
            enc_content: Some(vec![0u8; 20_000]),
            enc_nonce: Some([2u8; 24]),
            key_epoch: Some(0),
        };
        let edit_raw = signed(&sk, &author, MessageType::NewsEdit, original_ts + 1, rmp_serde::to_vec_named(&edit_payload).unwrap());

        let result = r.process_message(&edit_raw);
        assert!(
            matches!(&result, RouteResult::Rejected(msg) if msg.contains("may only target")),
            "expected a type-correspondence rejection, got {result:?}",
        );

        // The targeted ChatMessage must be completely untouched.
        let stored = r.storage.get_cf(schema::cf::MESSAGES, &original_id).unwrap().unwrap();
        let env: Envelope = rmp_serde::from_slice(&stored).unwrap();
        let p: ChatMessagePayload = rmp_serde::from_slice(&env.payload).unwrap();
        assert_eq!(p.enc_content, Some(vec![9, 9, 9]));
        assert_eq!(p.key_epoch, Some(1));
        assert!(p.content.is_empty());
    }

    #[test]
    fn chat_edit_cannot_target_a_news_post() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        store_message(&r, MessageType::NewsPost, &author, original_id, original_ts, news_post_payload());

        let edit_payload = EditPayload {
            target_id: original_id,
            channel_id: Some(42),
            content: "edited".to_string(),
            edited_at: original_ts + 1,
            title: None,
            tags: None,
            attachments: None,
            buttons: None,
            enc_content: None,
            enc_nonce: None,
            key_epoch: None,
        };
        let edit_raw = signed(&sk, &author, MessageType::ChatEdit, original_ts + 1, rmp_serde::to_vec_named(&edit_payload).unwrap());

        let result = r.process_message(&edit_raw);
        assert!(
            matches!(&result, RouteResult::Rejected(msg) if msg.contains("may only target")),
            "expected a type-correspondence rejection, got {result:?}",
        );
    }

    #[test]
    fn dm_edit_cannot_target_a_chat_message() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        store_message(&r, MessageType::ChatMessage, &author, original_id, original_ts, encrypted_chat_message_payload());

        let edit_payload = EditPayload {
            target_id: original_id,
            channel_id: None,
            content: String::new(),
            edited_at: original_ts + 1,
            title: None,
            tags: None,
            attachments: None,
            buttons: None,
            enc_content: Some(vec![7, 7, 7]),
            enc_nonce: Some([3u8; 24]),
            key_epoch: Some(1),
        };
        let edit_raw = signed(&sk, &author, MessageType::DirectMessageEdit, original_ts + 1, rmp_serde::to_vec_named(&edit_payload).unwrap());

        let result = r.process_message(&edit_raw);
        assert!(
            matches!(&result, RouteResult::Rejected(msg) if msg.contains("may only target")),
            "expected a type-correspondence rejection, got {result:?}",
        );
    }

    #[test]
    fn chat_delete_cannot_target_a_news_post() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        store_message(&r, MessageType::NewsPost, &author, original_id, original_ts, news_post_payload());

        let delete_payload = DeletePayload { target_id: original_id, channel_id: Some(42) };
        let delete_raw = signed(&sk, &author, MessageType::ChatDelete, original_ts + 1, rmp_serde::to_vec_named(&delete_payload).unwrap());

        let result = r.process_message(&delete_raw);
        assert!(
            matches!(&result, RouteResult::Rejected(msg) if msg.contains("may only target")),
            "expected a type-correspondence rejection, got {result:?}",
        );
    }

    /// Correctly-typed pairing must remain unaffected by the new check.
    #[test]
    fn news_edit_against_a_news_post_is_still_accepted() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let original_ts = now_ms();
        let original_id = [1u8; 32];
        store_message(&r, MessageType::NewsPost, &author, original_id, original_ts, news_post_payload());

        let edit_payload = EditPayload {
            target_id: original_id,
            channel_id: None,
            content: "updated body".to_string(),
            edited_at: original_ts + 1,
            title: None,
            tags: None,
            attachments: None,
            buttons: None,
            enc_content: None,
            enc_nonce: None,
            key_epoch: None,
        };
        let edit_raw = signed(&sk, &author, MessageType::NewsEdit, original_ts + 1, rmp_serde::to_vec_named(&edit_payload).unwrap());
        assert!(matches!(r.process_message(&edit_raw), RouteResult::Accepted { .. }));
    }
}

#[cfg(test)]
mod deletion_request_authorization_tests {
    //! Security-audit BLOCKING finding: `DeletionType::SingleMessage` had
    //! NO authorship check anywhere in the pipeline — `validate_deletion_request`
    //! only checks `target_id` is present, `authorize_channel_action` falls
    //! through to `Ok(())`, and the handler wrote a deletion marker for
    //! whatever `target_id` the sender supplied, regardless of who actually
    //! authored it. Since `is_deleted` is a bare key-existence check honored
    //! by every read, and `DeletionRequest` gossips network-wide, this was a
    //! working "delete anyone's message" primitive gated only by on-chain
    //! registration (a cost, not an authorization). These tests drive the
    //! new `authorize_deletion_request` check through the real
    //! `process_message` entry point.
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

    fn register_user(r: &MessageRouter, address: &str, registered_at: u64) {
        let rec = serde_json::json!({ "address": address, "registered_at": registered_at });
        r.storage
            .put_cf(schema::cf::USERS, address.as_bytes(), rec.to_string().as_bytes())
            .unwrap();
    }

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
            buttons: vec![],
            via_button: false,
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

    fn signed_single_message_deletion(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        target_id: [u8; 32],
        timestamp: u64,
    ) -> Vec<u8> {
        let payload = DeletionRequestPayload {
            delete_type: DeletionType::SingleMessage,
            target_id: Some(target_id),
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk, "testnet", crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::DeletionRequest as u8, &msg_id, timestamp, &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::DeletionRequest,
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

    /// THE regression this module exists to guard: before the fix, this
    /// exact sequence — a wallet with no relationship to the message at all,
    /// deleting a stranger's `ChatMessage` — was ACCEPTED and permanently
    /// tombstoned the message network-wide.
    #[test]
    fn deleting_another_authors_message_is_rejected() {
        let (r, _dir) = router();
        let victim_sk = crypto::generate_keypair();
        let victim = crypto::pubkey_to_address(&victim_sk.verifying_key()).unwrap();
        let attacker_sk = crypto::generate_keypair();
        let attacker = crypto::pubkey_to_address(&attacker_sk.verifying_key()).unwrap();
        register_user(&r, &attacker, 1_000);
        let channel_id = 42u64;
        let victim_ts = now_ms();
        let victim_msg_id = [1u8; 32];
        store_chat_message(&r, &victim, channel_id, victim_msg_id, victim_ts);

        let delete_raw = signed_single_message_deletion(&attacker_sk, &attacker, victim_msg_id, victim_ts + 1);
        assert!(matches!(r.process_message(&delete_raw), RouteResult::Rejected(_)));

        // The victim's message must still be readable — not tombstoned.
        assert!(!r.storage.is_deleted(&victim_msg_id).unwrap());
    }

    #[test]
    fn deleting_own_message_is_accepted() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let channel_id = 42u64;
        let ts = now_ms();
        let msg_id = [1u8; 32];
        store_chat_message(&r, &author, channel_id, msg_id, ts);

        let delete_raw = signed_single_message_deletion(&sk, &author, msg_id, ts + 1);
        assert!(matches!(r.process_message(&delete_raw), RouteResult::Accepted { .. }));
        assert!(r.storage.is_deleted(&msg_id).unwrap());
    }

    /// A `SingleMessage` deletion against a `target_id` the node has never
    /// seen is rejected outright rather than writing a marker on faith —
    /// there is no way to verify authorship of a message this node cannot
    /// look up.
    #[test]
    fn deleting_an_unknown_target_is_rejected() {
        let (r, _dir) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);
        let unknown_id = [0xAAu8; 32];

        let delete_raw = signed_single_message_deletion(&sk, &author, unknown_id, now_ms());
        assert!(matches!(r.process_message(&delete_raw), RouteResult::Rejected(_)));
        assert!(!r.storage.is_deleted(&unknown_id).unwrap());
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

// --- Bot descriptor: broadcast signalling (spec 01 §3.11, spec 03 §4.3) ---

#[cfg(test)]
mod bot_broadcast_signal_tests {
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
            ),
            dir,
        )
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    /// A fully signed ProfileUpdate carrying (or clearing) a bot descriptor.
    fn signed_profile_update(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        bot: Option<BotDescriptor>,
        timestamp: u64,
    ) -> Vec<u8> {
        let payload = ProfileUpdatePayload {
            display_name: Some("Chart Bot".into()),
            avatar_cid: None,
            bio: None,
            bot,
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ProfileUpdate as u8,
            &msg_id,
            timestamp,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ProfileUpdate,
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

    fn descriptor(desc: &str) -> BotDescriptor {
        BotDescriptor {
            is_bot: true,
            handle: Some("CoinTrendz".into()),
            commands: Some(vec![BotCommand {
                name: "c".into(),
                description: desc.into(),
                args_hint: None,
            }]),
        }
    }

    fn signal(r: &MessageRouter, raw: &[u8]) -> Option<String> {
        match r.process_message(raw) {
            RouteResult::Accepted { bot_commands_changed, .. } => bot_commands_changed,
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    fn sync_signal(r: &MessageRouter, raw: &[u8]) -> Option<String> {
        match r.process_synced_message(raw) {
            RouteResult::Accepted { bot_commands_changed, .. } => bot_commands_changed,
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn a_first_descriptor_signals_a_change() {
        let (r, _d) = router();
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let raw = signed_profile_update(&sk, &author, Some(descriptor("Chart")), now_ms());
        assert_eq!(signal(&r, &raw), Some(author));
    }

    #[test]
    fn an_identical_republish_does_not_signal() {
        // THE republish-on-start guarantee (spec 01 §3.11): a bot resends its
        // descriptor on every start, and the restart carries a FRESH timestamp —
        // so the LWW watermark alone would let every restart through to a
        // network-wide broadcast. Only the content comparison suppresses it.
        let (r, _d) = router();
        let sk = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let t = now_ms();
        assert_eq!(
            signal(&r, &signed_profile_update(&sk, &author, Some(descriptor("Chart")), t)),
            Some(author.clone())
        );
        // Same descriptor, strictly newer timestamp — passes LWW, must not signal.
        assert_eq!(
            signal(&r, &signed_profile_update(&sk, &author, Some(descriptor("Chart")), t + 1000)),
            None,
            "an identical republish must not trigger a broadcast"
        );
        // A real edit does signal.
        assert_eq!(
            signal(&r, &signed_profile_update(&sk, &author, Some(descriptor("Chart v2")), t + 2000)),
            Some(author)
        );
    }

    #[test]
    fn a_profile_edit_without_a_descriptor_never_signals() {
        let (r, _d) = router();
        let sk = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let t = now_ms();
        let _ = signal(&r, &signed_profile_update(&sk, &author, Some(descriptor("Chart")), t));
        assert_eq!(
            signal(&r, &signed_profile_update(&sk, &author, None, t + 1000)),
            None,
            "an ordinary display-name edit must not signal, and must not clear the descriptor"
        );
        // ...and the descriptor survived that edit.
        let rec: serde_json::Value = serde_json::from_slice(
            &r.storage.get_cf(schema::cf::USERS, author.as_bytes()).unwrap().unwrap(),
        )
        .unwrap();
        assert_eq!(rec["is_bot"], serde_json::json!(true));
        assert_eq!(rec["bot_commands"][0]["name"], serde_json::json!("c"));
    }

    #[test]
    fn identity_sync_never_signals() {
        // LOAD-BEARING (spec 03 §4.3): identity-sync deliberately bypasses rate
        // limiting, so if it could signal, a backfill of N profile updates would
        // emit N network-wide broadcasts that no rate limit could bound. The
        // gate is at the construction site, NOT at sync's call sites — this test
        // exists because relying on callers to discard the value made the
        // invariant true only by accident.
        let (r, _d) = router();
        let sk = ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]);
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let raw = signed_profile_update(&sk, &author, Some(descriptor("Chart")), now_ms());
        assert_eq!(
            sync_signal(&r, &raw),
            None,
            "process_synced_message must never signal a descriptor change"
        );
        // The descriptor IS still applied — only the broadcast is suppressed.
        let rec: serde_json::Value = serde_json::from_slice(
            &r.storage.get_cf(schema::cf::USERS, author.as_bytes()).unwrap().unwrap(),
        )
        .unwrap();
        assert_eq!(rec["is_bot"], serde_json::json!(true));
    }

    #[test]
    fn un_declaring_clears_the_descriptor_and_signals() {
        let (r, _d) = router();
        let sk = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let t = now_ms();
        let _ = signal(&r, &signed_profile_update(&sk, &author, Some(descriptor("Chart")), t));
        let cleared = BotDescriptor { is_bot: false, handle: None, commands: None };
        assert_eq!(
            signal(&r, &signed_profile_update(&sk, &author, Some(cleared), t + 1000)),
            Some(author.clone())
        );
        let rec: serde_json::Value = serde_json::from_slice(
            &r.storage.get_cf(schema::cf::USERS, author.as_bytes()).unwrap().unwrap(),
        )
        .unwrap();
        assert_eq!(rec["is_bot"], serde_json::json!(false));
        assert_eq!(rec["bot_handle"], serde_json::Value::Null);
        assert_eq!(rec["bot_commands"], serde_json::json!([]));
    }
}

#[cfg(test)]
mod route_result_author_tests {
    //! Design doc "Closing the Identity-Sync Coverage Gap" — `RouteResult::
    //! Accepted` gained an `author` field so `network::mod::handle_gossip_message`
    //! can drive the broadened identity-sync trigger without re-parsing
    //! `raw_bytes` itself. This covers the field is actually populated with
    //! the envelope's resolved author on real acceptance.
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

    fn register_user(r: &MessageRouter, address: &str, registered_at: u64) {
        let rec = serde_json::json!({ "address": address, "registered_at": registered_at });
        r.storage
            .put_cf(schema::cf::USERS, address.as_bytes(), rec.to_string().as_bytes())
            .unwrap();
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    fn signed_chat_envelope(
        sk: &ed25519_dalek::SigningKey,
        author: &str,
        channel_id: u64,
        timestamp: u64,
    ) -> Vec<u8> {
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
            buttons: vec![],
            via_button: false,
        };
        let payload_bytes = rmp_serde::to_vec_named(&payload).unwrap();
        let author_pubkey: [u8; 32] = sk.verifying_key().to_bytes();
        let msg_id =
            crypto::compute_msg_id("testnet", &author_pubkey, &payload_bytes, timestamp);
        let signature = signing::sign_ogmara_message(
            sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            MessageType::ChatMessage as u8,
            &msg_id,
            timestamp,
            &payload_bytes,
        );
        let envelope = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChatMessage,
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
    fn accepted_chat_message_carries_the_resolved_author() {
        let (r, _d) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);

        let raw = signed_chat_envelope(&sk, &author, 42, now_ms());
        match r.process_message(&raw) {
            RouteResult::Accepted { author: got, .. } => {
                assert_eq!(got, author, "author field must carry the resolved wallet");
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    #[test]
    fn resubmitting_an_accepted_envelope_is_still_a_plain_duplicate() {
        // `Duplicate` is a unit variant — adding a field to `Accepted` cannot
        // touch it at the type level. This just confirms duplicate detection
        // still works end-to-end after the change.
        let (r, _d) = router();
        let sk = crypto::generate_keypair();
        let author = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        register_user(&r, &author, 1_000);

        let raw = signed_chat_envelope(&sk, &author, 42, now_ms());
        assert!(matches!(r.process_message(&raw), RouteResult::Accepted { .. }));
        assert!(matches!(r.process_message(&raw), RouteResult::Duplicate));
    }

    #[test]
    fn accepted_result_uses_the_wallet_not_the_signing_device_key() {
        // A delegated device signs with its OWN key and `envelope.author` is
        // the device's ogd1... address — `resolved_author` (the wallet) and
        // `envelope.author` (the device) genuinely diverge here. A regression
        // that wired `Accepted.author` from `envelope.author` instead of
        // `resolved_author` would silently misattribute every delegated-
        // device message's identity-sync trigger to a device address that
        // has no USERS row and can never look "complete".
        let (r, _d) = router();
        let wallet_sk = crypto::generate_keypair();
        let wallet = crypto::pubkey_to_address(&wallet_sk.verifying_key()).unwrap();
        register_user(&r, &wallet, 1_000);

        let device_sk = crypto::generate_keypair();
        let device_address = crypto::device_pubkey_to_address(&device_sk.verifying_key()).unwrap();
        r.identity
            .register_device(&crate::storage::rocks::DeviceClaim {
                device_address: device_address.clone(),
                wallet_address: wallet.clone(),
                device_pubkey_hex: hex::encode(device_sk.verifying_key().to_bytes()),
                wallet_signature: "test".to_string(),
                registered_at: 1_000,
            })
            .unwrap();

        let raw = signed_chat_envelope(&device_sk, &device_address, 42, now_ms());
        match r.process_message(&raw) {
            RouteResult::Accepted { author: got, .. } => {
                assert_eq!(got, wallet, "must carry the resolved wallet, not the device key");
                assert_ne!(got, device_address);
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }
}

#[cfg(test)]
mod private_join_gate_tests {
    //! Private-channel join gate (l2-node 0.140.0, protocol §3.9.1). Every
    //! rule has an accept AND a reject case; envelopes are fully signed and
    //! go through the real `process_message` / `process_synced_message`
    //! pipeline unless a test targets a single helper.
    use super::*;
    use crate::messages::envelope::MAX_TIMESTAMP_DRIFT_MS as DRIFT;
    use tempfile::TempDir;

    /// A private-namespace channel id (above `PRIVATE_CHANNEL_ID_FLOOR`).
    const CID: u64 = (1u64 << 40) + 7;
    const DAY: u64 = 24 * 3600 * 1000;
    /// Activation far in the future: every join is "legacy".
    const FAR_FUTURE: u64 = u64::MAX / 2;

    struct W {
        sk: ed25519_dalek::SigningKey,
        addr: String,
    }

    fn wallet() -> W {
        let sk = crypto::generate_keypair();
        let addr = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        W { sk, addr }
    }

    fn router_with_activation(activation: u64) -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        let cfg = crate::config::ChannelVerifyConfig {
            private_join_proof_activation_ms: activation,
            ..Default::default()
        };
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
            .with_channel_verify_config(cfg),
            dir,
        )
    }

    /// Enforced from the start (mainnet setting).
    fn enforced() -> (MessageRouter, TempDir) {
        router_with_activation(0)
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    fn sign(w: &W, msg_type: MessageType, payload: Vec<u8>, ts: u64) -> Vec<u8> {
        let pk: [u8; 32] = w.sk.verifying_key().to_bytes();
        let msg_id = crypto::compute_msg_id("testnet", &pk, &payload, ts);
        let sig = signing::sign_ogmara_message(
            &w.sk,
            "testnet",
            crate::messages::envelope::PROTOCOL_VERSION,
            msg_type as u8,
            &msg_id,
            ts,
            &payload,
        );
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type,
            msg_id,
            author: w.addr.clone(),
            timestamp: ts,
            lamport_ts: 0,
            payload,
            signature: sig.to_bytes().to_vec(),
            relay_path: vec![],
        };
        rmp_serde::to_vec_named(&env).unwrap()
    }

    fn grant(creator: &W, cid: u64, target: &str, ts: u64) -> Vec<u8> {
        let p = ChannelAddModeratorPayload {
            channel_id: cid,
            target_user: target.to_string(),
            permissions: ModeratorPermissions {
                can_mute: true,
                can_kick: true,
                can_ban: true,
                can_pin: true,
                can_edit_info: false,
                can_delete_msgs: false,
            },
        };
        sign(creator, MessageType::ChannelAddModerator, rmp_serde::to_vec_named(&p).unwrap(), ts)
    }

    fn invite(
        inviter: &W,
        cid: u64,
        target: &str,
        ts: u64,
        expires_at: Option<u64>,
        inviter_grant: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let p = ChannelInvitePayload {
            channel_id: cid,
            target_user: target.to_string(),
            anchor_node: Some("https://host.example".to_string()),
            expires_at,
            inviter_grant,
        };
        sign(inviter, MessageType::ChannelInvite, rmp_serde::to_vec_named(&p).unwrap(), ts)
    }

    fn join(joiner: &W, cid: u64, invite: Option<Vec<u8>>, ts: u64) -> Vec<u8> {
        let p = ChannelJoinPayload { channel_id: cid, invite };
        sign(joiner, MessageType::ChannelJoin, rmp_serde::to_vec_named(&p).unwrap(), ts)
    }

    fn kick(by: &W, cid: u64, target: &str, ts: u64) -> Vec<u8> {
        let p = ChannelKickPayload { channel_id: cid, target_user: target.to_string(), reason: None };
        sign(by, MessageType::ChannelKick, rmp_serde::to_vec_named(&p).unwrap(), ts)
    }

    fn ban(by: &W, cid: u64, target: &str, ts: u64) -> Vec<u8> {
        let p = ChannelBanPayload {
            channel_id: cid,
            target_user: target.to_string(),
            reason: Some("test".into()),
            duration_secs: 0,
        };
        sign(by, MessageType::ChannelBan, rmp_serde::to_vec_named(&p).unwrap(), ts)
    }

    fn leave(w: &W, cid: u64, ts: u64) -> Vec<u8> {
        let p = ChannelLeavePayload { channel_id: cid };
        sign(w, MessageType::ChannelLeave, rmp_serde::to_vec_named(&p).unwrap(), ts)
    }

    fn remove_mod(creator: &W, cid: u64, target: &str, ts: u64) -> Vec<u8> {
        let p = ChannelRemoveModeratorPayload { channel_id: cid, target_user: target.to_string() };
        sign(creator, MessageType::ChannelRemoveModerator, rmp_serde::to_vec_named(&p).unwrap(), ts)
    }

    fn chat(w: &W, cid: u64, ts: u64) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct C {
            channel_id: u64,
            content: String,
        }
        let p = C { channel_id: cid, content: "hi".into() };
        sign(w, MessageType::ChatMessage, rmp_serde::to_vec_named(&p).unwrap(), ts)
    }

    fn register(r: &MessageRouter, addr: &str) {
        let rec = serde_json::json!({ "address": addr, "registered_at": 1_000u64 });
        r.storage.put_cf(schema::cf::USERS, addr.as_bytes(), rec.to_string().as_bytes()).unwrap();
    }

    fn make_channel(r: &MessageRouter, cid: u64, creator: &str, channel_type: u8) {
        let meta = serde_json::json!({
            "channel_id": cid,
            "channel_type": channel_type,
            "creator": creator,
            "member_count": 0u64,
        });
        r.storage.put_cf(schema::cf::CHANNELS, &cid.to_be_bytes(), meta.to_string().as_bytes()).unwrap();
        r.storage.add_channel_member(cid, creator, 1, "creator").unwrap();
        register(r, creator);
    }

    fn is_member(r: &MessageRouter, cid: u64, addr: &str) -> bool {
        r.storage
            .exists_cf(schema::cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(cid, addr))
            .unwrap()
    }

    fn accepted(res: &RouteResult) -> bool {
        if !matches!(res, RouteResult::Accepted { .. }) {
            eprintln!("not accepted: {res:?}");
        }
        matches!(res, RouteResult::Accepted { .. })
    }

    fn rejected_with(res: RouteResult, needle: &str) {
        match res {
            RouteResult::Rejected(r) => assert!(r.contains(needle), "unexpected reason: {r}"),
            other => panic!("expected Rejected containing {needle:?}, got {other:?}"),
        }
    }

    // ---- Rule 1: not private ----

    #[test]
    fn rule1_public_channel_join_needs_no_proof() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, 55, &c.addr, 0);
        assert!(accepted(&r.process_message(&join(&j, 55, None, now()))));
        assert!(is_member(&r, 55, &j.addr));
    }

    #[test]
    fn rule1_unknown_id_at_or_below_floor_is_public() {
        let (r, _d) = enforced();
        let j = wallet();
        assert_eq!(
            r.verify_private_join(PRIVATE_CHANNEL_ID_FLOOR, &j.addr, now(), None, false).map(|v| v.verdict),
            Ok(JoinVerdict::NotPrivate)
        );
    }

    #[test]
    fn rule1_reject_unknown_id_above_floor_is_private_and_needs_proof() {
        let (r, _d) = enforced();
        let j = wallet();
        rejected_with(r.process_message(&join(&j, CID, None, now())), "private channel: invite proof required");
    }

    // ---- Rule 2: shortcuts ----

    #[test]
    fn rule2_existing_member_and_creator_rejoin_without_proof() {
        let (r, _d) = enforced();
        let (c, m) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        r.storage.add_channel_member(CID, &m.addr, 1, "member").unwrap();
        assert!(accepted(&r.process_message(&join(&m, CID, None, now()))));
        assert!(accepted(&r.process_message(&join(&c, CID, None, now()))));
    }

    #[test]
    fn rule2_reject_non_member_without_proof() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        rejected_with(r.process_message(&join(&j, CID, None, now())), "private channel: invite proof required");
        assert!(!is_member(&r, CID, &j.addr));
    }

    // ---- Rule 3: activation ----

    #[test]
    fn rule3_proofless_live_join_before_activation_is_legacy_accepted() {
        let (r, _d) = router_with_activation(FAR_FUTURE);
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        assert!(accepted(&r.process_message(&join(&j, CID, None, now()))));
        assert!(is_member(&r, CID, &j.addr));
    }

    #[test]
    fn rule3_sync_legacy_join_vs_post_activation_sync_join() {
        let activation = now() - 10 * DAY;
        let (r, _d) = router_with_activation(activation);
        let (c, a, b) = (wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        // Backfilled history from before activation: accepted + applied.
        assert!(accepted(&r.process_synced_message(&join(&a, CID, None, activation - 1))));
        assert!(is_member(&r, CID, &a.addr));
        // A backdated-to-activation proofless join: rejected (boundary is exclusive).
        rejected_with(
            r.process_synced_message(&join(&b, CID, None, activation)),
            "private channel: invite proof required",
        );
        assert!(!is_member(&r, CID, &b.addr));
    }

    #[test]
    fn rule3_attached_bad_invite_is_verified_even_before_activation() {
        let (r, _d) = router_with_activation(FAR_FUTURE);
        let (c, j, other) = (wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        // Invite addressed to someone else — must NOT fall back to "no proof".
        let inv = invite(&c, CID, &other.addr, now() - 1_000, None, None);
        rejected_with(r.process_message(&join(&j, CID, Some(inv), now())), "different wallet");
        assert!(!is_member(&r, CID, &j.addr));
    }

    // ---- Rule 4: invite envelope ----

    #[test]
    fn rule4_valid_creator_invite_is_accepted_and_applied() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let inv = invite(&c, CID, &j.addr, now() - 1_000, None, None);
        assert!(accepted(&r.process_message(&join(&j, CID, Some(inv), now()))));
        assert!(is_member(&r, CID, &j.addr));
    }

    #[test]
    fn rule4_reject_tampered_signature() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let raw = invite(&c, CID, &j.addr, now() - 1_000, None, None);
        let mut env: Envelope = rmp_serde::from_slice(&raw).unwrap();
        env.signature[0] ^= 0xFF;
        let bad = rmp_serde::to_vec_named(&env).unwrap();
        rejected_with(r.process_message(&join(&j, CID, Some(bad), now())), "signature");
        assert!(!is_member(&r, CID, &j.addr));
    }

    #[test]
    fn rule4_reject_garbage_and_oversized_proof() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        rejected_with(r.process_message(&join(&j, CID, Some(vec![1, 2, 3]), now())), "not a valid envelope");
        // Size cap is structural (validation), applies on every channel type.
        rejected_with(
            r.process_message(&join(&j, CID, Some(vec![0u8; validation::MAX_JOIN_INVITE_BYTES + 1]), now())),
            "invite proof must be",
        );
        make_channel(&r, 56, &c.addr, 0);
        rejected_with(
            r.process_message(&join(&j, 56, Some(vec![0u8; validation::MAX_JOIN_INVITE_BYTES + 1]), now())),
            "invite proof must be",
        );
    }

    #[test]
    fn rule4_reject_nested_type_confusion() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        // A creator-signed ChannelAddModerator smuggled in the invite slot.
        let g = grant(&c, CID, &j.addr, now() - 2_000);
        rejected_with(r.process_message(&join(&j, CID, Some(g), now())), "expected ChannelInvite");
        // A ChannelJoin nested as the "invite".
        let inner = join(&j, CID, None, now() - 1_000);
        rejected_with(r.process_message(&join(&j, CID, Some(inner), now())), "expected ChannelInvite");
        // An invite whose `inviter_grant` is itself an invite.
        let m = wallet();
        let fake_grant = invite(&c, CID, &m.addr, now() - 3_000, None, None);
        let inv = invite(&m, CID, &j.addr, now() - 1_000, None, Some(fake_grant));
        rejected_with(r.process_message(&join(&j, CID, Some(inv), now())), "inviter is not creator or moderator");
        assert!(!is_member(&r, CID, &j.addr));
    }

    // ---- Rule 5: binding ----

    #[test]
    fn rule5_reject_forwarded_invite_and_wrong_channel() {
        let (r, _d) = enforced();
        let (c, j, friend) = (wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let for_friend = invite(&c, CID, &friend.addr, now() - 1_000, None, None);
        rejected_with(r.process_message(&join(&j, CID, Some(for_friend.clone()), now())), "different wallet");
        let other_channel = invite(&c, CID + 1, &j.addr, now() - 1_000, None, None);
        rejected_with(r.process_message(&join(&j, CID, Some(other_channel), now())), "different channel");
        // The named friend is still admitted by the same bytes.
        assert!(accepted(&r.process_message(&join(&friend, CID, Some(for_friend), now()))));
    }

    // ---- Rule 6: time ----

    #[test]
    fn rule6_expiry_default_ttl_live() {
        let (r, _d) = enforced();
        let (c, j, k) = (wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        // 6.9 days old, default 7d TTL: still valid.
        let fresh = invite(&c, CID, &j.addr, now() - 7 * DAY + 60_000, None, None);
        assert!(accepted(&r.process_message(&join(&j, CID, Some(fresh), now()))));
        // 7d + 1 min old: expired.
        let stale = invite(&c, CID, &k.addr, now() - 7 * DAY - 60_000, None, None);
        rejected_with(r.process_message(&join(&k, CID, Some(stale), now())), "expired");
    }

    #[test]
    fn rule6_explicit_expires_at_and_ttl_bounds() {
        let (r, _d) = enforced();
        let (c, j, k, l) = (wallet(), wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let ts = now() - 1_000;
        // 1h validity, still inside.
        assert!(accepted(&r.process_message(&join(&j, CID, Some(invite(&c, CID, &j.addr, ts, Some(ts + 3_600_000), None)), now()))));
        // Already past an explicit short expiry.
        let short = invite(&c, CID, &k.addr, ts, Some(ts + 500), None);
        rejected_with(r.process_message(&join(&k, CID, Some(short), now())), "expired");
        // expires_at beyond MAX_INVITE_TTL is malformed.
        let too_long = invite(&c, CID, &l.addr, ts, Some(ts + validation::MAX_INVITE_TTL_MS + 1), None);
        rejected_with(r.process_message(&join(&l, CID, Some(too_long), now())), "maximum invite lifetime");
        // expires_at at/before the invite ts is malformed.
        let backwards = invite(&c, CID, &l.addr, ts, Some(ts), None);
        rejected_with(r.process_message(&join(&l, CID, Some(backwards), now())), "after the invite");
    }

    #[test]
    fn rule6_future_invite_beyond_drift_rejected_within_drift_accepted() {
        let (r, _d) = enforced();
        let (c, j, k) = (wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let join_ts = now() - 30 * DAY; // historical, via sync
        let ahead = invite(&c, CID, &j.addr, join_ts + DRIFT + 1, None, None);
        rejected_with(r.process_synced_message(&join(&j, CID, Some(ahead), join_ts)), "dated after the join");
        let skewed = invite(&c, CID, &k.addr, join_ts + DRIFT, None, None);
        assert!(accepted(&r.process_synced_message(&join(&k, CID, Some(skewed), join_ts))));
    }

    #[test]
    fn rule6_historical_join_still_valid_on_backfill_after_its_invite_expired() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let t = now() - 60 * DAY;
        let inv = invite(&c, CID, &j.addr, t - 1_000, None, None);
        // Live: the same invite is long expired.
        rejected_with(r.process_message(&join(&j, CID, Some(inv.clone()), now())), "expired");
        // Sync: the historical join used it in time — envelope clocks only.
        assert!(accepted(&r.process_synced_message(&join(&j, CID, Some(inv), t))));
        assert!(is_member(&r, CID, &j.addr));
    }

    // ---- Rule 7: removal cutoff ----

    #[test]
    fn rule7_kicked_user_cannot_replay_old_invite_but_fresh_invite_works() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let old = invite(&c, CID, &j.addr, now() - 10_000, None, None);
        assert!(accepted(&r.process_message(&join(&j, CID, Some(old.clone()), now() - 5_000))));
        assert!(accepted(&r.process_message(&kick(&c, CID, &j.addr, now() - 2_000))));
        assert!(!is_member(&r, CID, &j.addr));
        rejected_with(r.process_message(&join(&j, CID, Some(old), now())), "predates the joiner's removal");
        assert!(!is_member(&r, CID, &j.addr));
        let fresh = invite(&c, CID, &j.addr, now() - 1_000, None, None);
        assert!(accepted(&r.process_message(&join(&j, CID, Some(fresh), now()))));
        assert!(is_member(&r, CID, &j.addr));
    }

    #[test]
    fn rule7_ban_cutoff_outlives_unban() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let old = invite(&c, CID, &j.addr, now() - 10_000, None, None);
        assert!(accepted(&r.process_message(&ban(&c, CID, &j.addr, now() - 5_000))));
        r.storage.delete_cf(schema::cf::CHANNEL_BANS, &schema::encode_channel_ban_key(CID, &j.addr)).unwrap();
        rejected_with(r.process_message(&join(&j, CID, Some(old), now())), "predates the joiner's removal");
    }

    #[test]
    fn rule7_voluntary_leave_writes_no_cutoff() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let inv = invite(&c, CID, &j.addr, now() - 10_000, None, None);
        assert!(accepted(&r.process_message(&join(&j, CID, Some(inv.clone()), now() - 5_000))));
        assert!(accepted(&r.process_message(&leave(&j, CID, now() - 2_000))));
        assert!(r.storage.channel_removal_cutoff(CID, &j.addr).unwrap().is_none());
        assert!(accepted(&r.process_message(&join(&j, CID, Some(inv), now()))));
        assert!(is_member(&r, CID, &j.addr));
    }

    #[test]
    fn apply_step_backfilled_join_after_its_superseding_kick_is_not_applied() {
        // Backfill delivers the kick (t2) BEFORE the legacy join (t1 < t2):
        // the join is a valid historical message (Accepted) but must not
        // resurrect the member.
        let (r, _d) = router_with_activation(FAR_FUTURE);
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let t1 = now() - 10 * DAY;
        assert!(accepted(&r.process_synced_message(&kick(&c, CID, &j.addr, t1 + 1_000))));
        assert!(accepted(&r.process_synced_message(&join(&j, CID, None, t1))));
        assert!(!is_member(&r, CID, &j.addr));
        // Tie: removal wins.
        let k = wallet();
        assert!(accepted(&r.process_synced_message(&kick(&c, CID, &k.addr, t1))));
        assert!(accepted(&r.process_synced_message(&join(&k, CID, None, t1))));
        assert!(!is_member(&r, CID, &k.addr));
        // Control: a join AFTER the kick is applied.
        assert!(accepted(&r.process_synced_message(&join(&j, CID, None, t1 + 2_000))));
        assert!(is_member(&r, CID, &j.addr));
    }

    /// Round-5 S-W1: J1, J3 (held no-op re-join while a member), then the
    /// OLDER leave L2 arrives late. The index promotes J3, so a late node
    /// replays J1 → L2 → J3; this node must converge to the same state
    /// instead of applying the leave unconditionally.
    #[test]
    fn late_leave_before_a_held_rejoin_converges_with_a_late_node() {
        let (r, _d) = router_with_activation(FAR_FUTURE);
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let t = now() - 10 * DAY;
        let (j1, l2, j3) = (join(&j, CID, None, t), leave(&j, CID, t + 1_000), join(&j, CID, None, t + 2_000));
        assert!(accepted(&r.process_synced_message(&j1)));
        assert!(accepted(&r.process_synced_message(&j3)));
        assert!(is_member(&r, CID, &j.addr));
        assert!(accepted(&r.process_synced_message(&l2)));
        assert!(is_member(&r, CID, &j.addr), "the newer rejoin must survive the late leave");
        // Late node: chronological replay of the same envelopes.
        let (late, _d2) = router_with_activation(FAR_FUTURE);
        make_channel(&late, CID, &c.addr, 2);
        for e in [&j1, &l2, &j3] {
            assert!(accepted(&late.process_synced_message(e)));
        }
        assert!(is_member(&late, CID, &j.addr));

        // Negative control: the late leave is NEWER than the held rejoin.
        let k = wallet();
        assert!(accepted(&r.process_synced_message(&join(&k, CID, None, t))));
        assert!(accepted(&r.process_synced_message(&join(&k, CID, None, t + 1_000))));
        assert!(accepted(&r.process_synced_message(&leave(&k, CID, t + 2_000))));
        assert!(!is_member(&r, CID, &k.addr));

        // Equal timestamps: the leave wins (as on a late node, which never
        // gets the tied rejoin indexed). The rejoin carries an invite only
        // so its payload — and so its msg_id, which does not cover the
        // msg_type — differs from the leave's.
        let m = wallet();
        assert!(accepted(&r.process_synced_message(&join(&m, CID, None, t))));
        let inv_m = invite(&c, CID, &m.addr, t + 1_000, None, None);
        assert!(accepted(&r.process_synced_message(&join(&m, CID, Some(inv_m), t + 2_000))));
        assert!(accepted(&r.process_synced_message(&leave(&m, CID, t + 2_000))));
        assert!(!is_member(&r, CID, &m.addr));
    }

    /// Round-5 S-W1, enforced private channel: the held rejoin carried NO
    /// invite (a member needs none). Re-applied after the late leave it is
    /// re-gated from scratch — as on a late node, where the same join
    /// arrives after the leave and is refused — so both end non-member.
    /// With its own invite it is applied on both.
    #[test]
    fn late_leave_reapplied_rejoin_is_regated_like_on_a_late_node() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let t = now() - 60_000;
        let inv = invite(&c, CID, &j.addr, t - 1_000, None, None);
        assert!(accepted(&r.process_synced_message(&join(&j, CID, Some(inv.clone()), t))));
        let j3 = join(&j, CID, None, t + 2_000);
        assert!(accepted(&r.process_synced_message(&j3)));
        assert!(accepted(&r.process_synced_message(&leave(&j, CID, t + 1_000))));
        assert!(!is_member(&r, CID, &j.addr), "a proofless rejoin must not survive re-gating");
        // Late node: L2 makes J3 a non-member join without proof → refused.
        let (late, _d2) = enforced();
        make_channel(&late, CID, &c.addr, 2);
        assert!(accepted(&late.process_synced_message(&join(&j, CID, Some(inv.clone()), t))));
        assert!(accepted(&late.process_synced_message(&leave(&j, CID, t + 1_000))));
        rejected_with(late.process_synced_message(&j3), "invite proof required");
        assert!(!is_member(&late, CID, &j.addr));

        // Same shape, the rejoin carries its own invite: member.
        let k = wallet();
        let inv_k = invite(&c, CID, &k.addr, t - 1_000, None, None);
        assert!(accepted(&r.process_synced_message(&join(&k, CID, Some(inv_k.clone()), t))));
        assert!(accepted(&r.process_synced_message(&join(&k, CID, Some(inv_k), t + 2_000))));
        assert!(accepted(&r.process_synced_message(&leave(&k, CID, t + 1_000))));
        assert!(is_member(&r, CID, &k.addr));
    }

    /// Round-6: the S-W1 re-apply must never undo a ban. Public channel:
    /// J@t, J@t+3 (held no-op re-join), Ban@t+4, then the late L@t+2
    /// promotes J@t+3 — the re-applied join is refused (active ban in
    /// `recheck_join_locked`, plus the ban's REMOVED watermark at t+4).
    #[test]
    fn late_leave_after_ban_does_not_readd_the_banned_member() {
        let (r, _d) = enforced();
        let c = wallet();
        make_channel(&r, CID, &c.addr, 0);
        let t = now() - 10 * DAY;
        // Positive control: without the ban the late leave re-applies the
        // held rejoin (so the refusals below are the re-apply's, not a
        // path that never ran).
        let k = wallet();
        assert!(accepted(&r.process_synced_message(&join(&k, CID, None, t))));
        assert!(accepted(&r.process_synced_message(&join(&k, CID, None, t + 3_000))));
        assert!(accepted(&r.process_synced_message(&leave(&k, CID, t + 2_000))));
        assert!(is_member(&r, CID, &k.addr), "control: held rejoin re-applied");

        let j = wallet();
        assert!(accepted(&r.process_synced_message(&join(&j, CID, None, t))));
        assert!(accepted(&r.process_synced_message(&join(&j, CID, None, t + 3_000))));
        assert!(accepted(&r.process_synced_message(&ban(&c, CID, &j.addr, t + 4_000))));
        assert!(!is_member(&r, CID, &j.addr));
        let _ = r.process_synced_message(&leave(&j, CID, t + 2_000));
        assert!(!is_member(&r, CID, &j.addr), "a late leave must not re-add a banned member");

        // Same shape with the REMOVED watermark absent (a ban recorded
        // before 0.140.0 wrote no watermark): only the active-ban re-check
        // stands between the re-apply and the member row.
        let b = wallet();
        assert!(accepted(&r.process_synced_message(&join(&b, CID, None, t))));
        assert!(accepted(&r.process_synced_message(&join(&b, CID, None, t + 3_000))));
        assert!(accepted(&r.process_synced_message(&ban(&c, CID, &b.addr, t + 4_000))));
        r.storage
            .delete_cf(
                schema::cf::CHANNEL_ROLE_WATERMARKS,
                &schema::encode_channel_role_watermark_key(CID, schema::role_watermark_kind::REMOVED, &b.addr),
            )
            .unwrap();
        assert!(r.storage.channel_removal_cutoff(CID, &b.addr).unwrap().is_none());
        let _ = r.process_synced_message(&leave(&b, CID, t + 2_000));
        assert!(!is_member(&r, CID, &b.addr), "the active ban alone must refuse the re-apply");
    }

    /// Round-6: kick mirror of the above. J@t, J@t+3 (held), Kick@t+4, late
    /// L@t+2 — the re-applied J@t+3 is refused by the kick's REMOVED
    /// watermark (t+4 >= t+3) in `add_channel_member_checked`.
    #[test]
    fn late_leave_after_kick_does_not_readd_the_kicked_member() {
        let (r, _d) = enforced();
        let c = wallet();
        make_channel(&r, CID, &c.addr, 0);
        let t = now() - 10 * DAY;
        let j = wallet();
        assert!(accepted(&r.process_synced_message(&join(&j, CID, None, t))));
        assert!(accepted(&r.process_synced_message(&join(&j, CID, None, t + 3_000))));
        assert!(accepted(&r.process_synced_message(&kick(&c, CID, &j.addr, t + 4_000))));
        assert!(!is_member(&r, CID, &j.addr));
        let _ = r.process_synced_message(&leave(&j, CID, t + 2_000));
        assert!(!is_member(&r, CID, &j.addr), "a late leave must not re-add a kicked member");
        // A join AFTER the kick is still applied (the watermark only
        // shadows joins at or before it).
        assert!(accepted(&r.process_synced_message(&join(&j, CID, None, t + 5_000))));
        assert!(is_member(&r, CID, &j.addr));
    }

    #[test]
    fn removal_watermark_is_max_and_clamped() {
        let (r, _d) = enforced();
        r.storage.raise_channel_role_watermark(CID, schema::role_watermark_kind::REMOVED, "klv1x", 500).unwrap();
        r.storage.raise_channel_role_watermark(CID, schema::role_watermark_kind::REMOVED, "klv1x", 200).unwrap();
        assert_eq!(r.storage.channel_removal_cutoff(CID, "klv1x").unwrap(), Some(500));
        let far = now() + 365 * DAY;
        assert!(MessageRouter::clamp_watermark_ts(far) <= now() + DRIFT + 1_000);
        assert_eq!(MessageRouter::clamp_watermark_ts(500), 500);
    }

    // ---- Rule 8: inviter authority ----

    #[test]
    fn rule8_moderator_with_grant_accepted_on_node_that_does_not_know_moderators() {
        let (r, _d) = enforced();
        let (c, m, j) = (wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let g = grant(&c, CID, &m.addr, now() - 5_000);
        let inv = invite(&m, CID, &j.addr, now() - 1_000, None, Some(g));
        assert!(accepted(&r.process_message(&join(&j, CID, Some(inv), now()))));
        assert!(is_member(&r, CID, &j.addr));
    }

    #[test]
    fn rule8_reject_non_moderator_without_grant() {
        let (r, _d) = enforced();
        let (c, m, j) = (wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let inv = invite(&m, CID, &j.addr, now() - 1_000, None, None);
        rejected_with(r.process_message(&join(&j, CID, Some(inv), now())), "private channel: inviter is not creator or moderator");
    }

    #[test]
    fn rule8_locally_known_moderator_without_grant_is_accepted() {
        let (r, _d) = enforced();
        let (c, m, j) = (wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        r.storage.put_cf(schema::cf::CHANNEL_MODERATORS, &schema::encode_channel_moderator_key(CID, &m.addr), b"{}").unwrap();
        let inv = invite(&m, CID, &j.addr, now() - 1_000, None, None);
        assert!(accepted(&r.process_message(&join(&j, CID, Some(inv), now()))));
    }

    #[test]
    fn rule8_reject_forged_wrong_target_and_future_grants() {
        let (r, _d) = enforced();
        let (c, m, j, impostor) = (wallet(), wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        // Forged: "grant" signed by someone who is not the creator.
        let forged = grant(&impostor, CID, &m.addr, now() - 5_000);
        let inv = invite(&m, CID, &j.addr, now() - 1_000, None, Some(forged));
        rejected_with(r.process_message(&join(&j, CID, Some(inv), now())), "inviter is not creator or moderator");
        // Genuine grant, but for a different wallet than the inviter.
        let other = grant(&c, CID, &impostor.addr, now() - 5_000);
        let inv = invite(&m, CID, &j.addr, now() - 1_000, None, Some(other));
        rejected_with(r.process_message(&join(&j, CID, Some(inv), now())), "inviter is not creator or moderator");
        // Genuine grant for a different channel.
        let other_ch = grant(&c, CID + 1, &m.addr, now() - 5_000);
        let inv = invite(&m, CID, &j.addr, now() - 1_000, None, Some(other_ch));
        rejected_with(r.process_message(&join(&j, CID, Some(inv), now())), "inviter is not creator or moderator");
        // grant.ts > invite.ts.
        let later = grant(&c, CID, &m.addr, now() - 500);
        let inv = invite(&m, CID, &j.addr, now() - 1_000, None, Some(later));
        rejected_with(r.process_message(&join(&j, CID, Some(inv), now())), "inviter is not creator or moderator");
        assert!(!is_member(&r, CID, &j.addr));
    }

    #[test]
    fn rule8_demoted_moderator_live_vs_sync() {
        let (r, _d) = enforced();
        let (c, m, j, k) = (wallet(), wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let g_ts = now() - 20 * 60_000;
        let g = grant(&c, CID, &m.addr, g_ts);
        let inv_j = invite(&m, CID, &j.addr, g_ts + 1_000, None, Some(g.clone()));
        let inv_k = invite(&m, CID, &k.addr, g_ts + 1_000, None, Some(g));
        // Demotion after the invites were issued.
        assert!(accepted(&r.process_message(&remove_mod(&c, CID, &m.addr, now() - 60_000))));
        // Live join now: the demoted moderator's outstanding invite is dead.
        rejected_with(r.process_message(&join(&j, CID, Some(inv_j), now())), "inviter is not creator or moderator");
        // Historical (sync) join that happened before the demotion: still valid history.
        assert!(accepted(&r.process_synced_message(&join(&k, CID, Some(inv_k), g_ts + 2_000))));
        assert!(is_member(&r, CID, &k.addr));
    }

    #[test]
    fn invited_unknown_channel_is_accepted_but_not_applied() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        let inv = invite(&c, CID, &j.addr, now() - 1_000, None, None);
        assert_eq!(
            r.verify_private_join(CID, &j.addr, now(), Some(&inv), false).map(|v| v.verdict),
            Ok(JoinVerdict::InvitedUnknownChannel)
        );
        assert!(accepted(&r.process_message(&join(&j, CID, Some(inv), now()))));
        assert!(!is_member(&r, CID, &j.addr));
        // Rules 4-7 still run for an unknown channel.
        let wrong = invite(&c, CID, &c.addr, now() - 1_000, None, None);
        rejected_with(r.process_message(&join(&j, CID, Some(wrong), now())), "different wallet");
    }

    // ---- Chat no-auto-add (B1) ----

    #[test]
    fn chat_in_private_channel_no_longer_auto_adds_but_is_accepted() {
        let (r, _d) = enforced();
        let (c, x) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        assert!(accepted(&r.process_message(&chat(&x, CID, now()))));
        assert!(!is_member(&r, CID, &x.addr));
    }

    #[test]
    fn chat_legacy_and_public_still_auto_add() {
        let (r, _d) = router_with_activation(FAR_FUTURE);
        let (c, x, y) = (wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        assert!(accepted(&r.process_message(&chat(&x, CID, now()))));
        assert!(is_member(&r, CID, &x.addr));
        make_channel(&r, 57, &c.addr, 0);
        let (r2, _d2) = enforced();
        make_channel(&r2, 57, &c.addr, 0);
        assert!(accepted(&r2.process_message(&chat(&y, 57, now()))));
        assert!(is_member(&r2, 57, &y.addr));
    }

    #[test]
    fn chat_legacy_auto_add_respects_newer_kick() {
        let (r, _d) = router_with_activation(FAR_FUTURE);
        let (c, x) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let t = now() - DAY;
        assert!(accepted(&r.process_synced_message(&kick(&c, CID, &x.addr, t + 1_000))));
        assert!(accepted(&r.process_synced_message(&chat(&x, CID, t))));
        assert!(!is_member(&r, CID, &x.addr));
    }

    // ---- ChannelInvite ingest ----

    #[test]
    fn invite_ingest_grant_on_node_without_moderators_accepted_plain_non_mod_rejected() {
        let (r, _d) = enforced();
        let (c, m, t) = (wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        register(&r, &m.addr);
        let g = grant(&c, CID, &m.addr, now() - 5_000);
        assert!(accepted(&r.process_message(&invite(&m, CID, &t.addr, now(), None, Some(g)))));
        rejected_with(r.process_message(&invite(&m, CID, &t.addr, now() + 1, None, None)), "only creator or moderators");
    }

    #[test]
    fn invite_ingest_demoted_moderator_grant_rejected() {
        let (r, _d) = enforced();
        let (c, m, t) = (wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        register(&r, &m.addr);
        let g = grant(&c, CID, &m.addr, now() - 50_000);
        assert!(accepted(&r.process_message(&remove_mod(&c, CID, &m.addr, now() - 10_000))));
        rejected_with(r.process_message(&invite(&m, CID, &t.addr, now(), None, Some(g))), "only creator or moderators");
    }

    #[test]
    fn invite_ingest_bad_expiry_and_oversized_grant_rejected() {
        let (r, _d) = enforced();
        let (c, t) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let ts = now();
        rejected_with(r.process_message(&invite(&c, CID, &t.addr, ts, Some(ts + validation::MAX_INVITE_TTL_MS + 1), None)), "maximum invite lifetime");
        rejected_with(r.process_message(&invite(&c, CID, &t.addr, ts + 1, Some(ts), None)), "after the invite");
        rejected_with(r.process_message(&invite(&c, CID, &t.addr, ts + 2, None, Some(vec![0u8; validation::MAX_INVITER_GRANT_BYTES + 1]))), "inviter_grant");
        assert!(accepted(&r.process_message(&invite(&c, CID, &t.addr, ts + 3, Some(ts + 3 + validation::MAX_INVITE_TTL_MS), None))));
    }

    // ---- Federate gates ----

    #[test]
    fn federate_prefetch_gate_unknown_channel_and_invite_rules() {
        let (r, _d) = enforced();
        let (c, j, m) = (wallet(), wallet(), wallet());
        // Unknown channel, no invite: allowed to fetch — the caller may be
        // the creator; `federate_bootstrap_gate` decides before storing.
        assert!(r.federate_prefetch_gate(CID, &j.addr, now(), None).is_ok());
        let inv = invite(&c, CID, &j.addr, now() - 1_000, None, None);
        assert!(r.federate_prefetch_gate(CID, &j.addr, now(), Some(&inv)).is_ok());
        // An attached invite must still pass rules 4-7.
        assert!(r.federate_prefetch_gate(CID, &m.addr, now(), Some(&inv)).is_err());
        let old = invite(&c, CID, &j.addr, now() - 8 * DAY, None, None);
        assert!(r.federate_prefetch_gate(CID, &j.addr, now(), Some(&old)).is_err());
        // Known channel: non-member without invite is refused before any fetch.
        make_channel(&r, CID, &c.addr, 2);
        assert_eq!(
            r.federate_prefetch_gate(CID, &j.addr, now(), None).unwrap_err(),
            "private channel: invite proof required"
        );
        // Known channel, already a member: refresh allowed without invite.
        r.storage.add_channel_member(CID, &m.addr, 1, "member").unwrap();
        assert!(r.federate_prefetch_gate(CID, &m.addr, now(), None).is_ok());
    }

    #[test]
    fn federate_prefetch_gate_known_channel_runs_full_inviter_authority() {
        // Round-2 audit N-b: for a channel this node already knows, a
        // self-signed (non-moderator) invite must be refused BEFORE any
        // outbound fetch / envelope replay / federated_from rewrite.
        let (r, _d) = enforced();
        let (c, x, j) = (wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let selfish = invite(&x, CID, &x.addr, now() - 1_000, None, None);
        assert_eq!(
            r.federate_prefetch_gate(CID, &x.addr, now(), Some(&selfish)).unwrap_err(),
            "private channel: inviter is not creator or moderator"
        );
        let genuine = invite(&c, CID, &j.addr, now() - 1_000, None, None);
        assert!(r.federate_prefetch_gate(CID, &j.addr, now(), Some(&genuine)).is_ok());
    }

    #[test]
    fn federate_prefetch_gate_passes_known_public_channels_to_the_400() {
        // Round-3: a non-member with no invite federating a known PUBLIC
        // channel must get the specified 400, not a private-channel 403.
        let (r, _d) = enforced();
        let (c, x) = (wallet(), wallet());
        make_channel(&r, 55, &c.addr, 0);
        make_channel(&r, 56, &c.addr, 1);
        assert!(r.federate_prefetch_gate(55, &x.addr, now(), None).is_ok());
        assert!(r.federate_prefetch_gate(56, &x.addr, now(), None).is_ok());
    }

    #[test]
    fn creator_without_member_row_is_added_with_creator_role() {
        // Round-3 N4.
        let (r, _d) = enforced();
        let c = wallet();
        make_channel(&r, CID, &c.addr, 2);
        r.storage
            .delete_cf(schema::cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(CID, &c.addr))
            .unwrap();
        let v = r.federate_membership_gate(CID, &c.addr, now(), None).unwrap();
        assert!(r.federate_add_member(CID, &c.addr, now(), &v).unwrap());
        let rec = r
            .storage
            .get_cf(schema::cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(CID, &c.addr))
            .unwrap()
            .unwrap();
        let rec: serde_json::Value = serde_json::from_slice(&rec).unwrap();
        assert_eq!(rec["role"], "creator");
    }

    #[test]
    fn federate_prefetch_gate_has_no_activation_exemption() {
        let (r, _d) = router_with_activation(FAR_FUTURE);
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        assert!(r.federate_prefetch_gate(CID, &j.addr, now(), None).is_err());
    }

    #[test]
    fn federate_membership_gate_ban_authority_and_refresh() {
        let (r, _d) = enforced();
        let (c, j, b, m, x) = (wallet(), wallet(), wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let inv = invite(&c, CID, &j.addr, now() - 1_000, None, None);
        assert_eq!(r.federate_membership_gate(CID, &j.addr, now(), Some(&inv)).map(|v| v.verdict), Ok(JoinVerdict::Invited));
        // Banned: rejected even with a valid fresh invite.
        assert!(accepted(&r.process_message(&ban(&c, CID, &b.addr, now() - 5_000))));
        let inv_b = invite(&c, CID, &b.addr, now() - 1_000, None, None);
        assert!(r.federate_membership_gate(CID, &b.addr, now(), Some(&inv_b)).unwrap_err().contains("banned"));
        // Non-moderator inviter: rejected after bootstrap.
        let bad = invite(&x, CID, &m.addr, now() - 1_000, None, None);
        assert!(r.federate_membership_gate(CID, &m.addr, now(), Some(&bad)).is_err());
        // Refresh by an existing member: no invite needed.
        r.storage.add_channel_member(CID, &m.addr, 1, "member").unwrap();
        assert_eq!(r.federate_membership_gate(CID, &m.addr, now(), None).map(|v| v.verdict), Ok(JoinVerdict::AlreadyMemberOrCreator));
    }

    // ---- Storage: purge + moderator LWW + grant lookup ----

    #[test]
    fn channel_invites_purge_is_capped_and_idempotent() {
        let (r, _d) = enforced();
        for i in 0..5u64 {
            r.storage.put_cf(schema::cf::CHANNEL_INVITES, &schema::encode_channel_invite_key(i + 1, "klv1a"), b"{}").unwrap();
        }
        assert_eq!(r.storage.run_channel_invites_purge(3).unwrap(), 3);
        assert_eq!(r.storage.get_stat(schema::state_keys::CHANNEL_INVITES_PURGED).unwrap(), 0);
        assert_eq!(r.storage.run_channel_invites_purge(3).unwrap(), 2);
        assert_eq!(r.storage.get_stat(schema::state_keys::CHANNEL_INVITES_PURGED).unwrap(), 1);
        assert_eq!(r.storage.prefix_iter_cf(schema::cf::CHANNEL_INVITES, &[], 10).unwrap().len(), 0);
        // Sentinel set: later passes do nothing, even if a stray row appears.
        r.storage.put_cf(schema::cf::CHANNEL_INVITES, b"stray", b"{}").unwrap();
        assert_eq!(r.storage.run_channel_invites_purge(3).unwrap(), 0);
    }

    #[test]
    fn moderator_grant_record_lww_and_demotion_ordering() {
        let (r, _d) = enforced();
        let (c, m) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let t = now() - DAY;
        let newer = grant(&c, CID, &m.addr, t + 2_000);
        let older = grant(&c, CID, &m.addr, t + 1_000);
        assert!(accepted(&r.process_synced_message(&newer)));
        assert!(accepted(&r.process_synced_message(&older)));
        let looked = crate::api::routes::lookup_moderator_grant(&r.storage, CID, &m.addr).unwrap().unwrap();
        assert_eq!(looked, newer, "an older grant must not replace grant_msg_id");
        assert_eq!(crate::api::routes::lookup_moderator_grant(&r.storage, CID, &c.addr).unwrap(), None);
        // An older demotion replayed later must not delete the newer grant.
        assert!(accepted(&r.process_synced_message(&remove_mod(&c, CID, &m.addr, t + 1_500))));
        assert!(r.storage.is_channel_moderator(CID, &m.addr).unwrap());
        // A newer demotion does; an older grant replayed afterwards can't reinstate.
        assert!(accepted(&r.process_synced_message(&remove_mod(&c, CID, &m.addr, t + 3_000))));
        assert!(!r.storage.is_channel_moderator(CID, &m.addr).unwrap());
        let old2 = grant(&c, CID, &m.addr, t + 2_500);
        assert!(accepted(&r.process_synced_message(&old2)));
        assert!(!r.storage.is_channel_moderator(CID, &m.addr).unwrap());
        // Both moderator types are indexed for backfill (B5).
        let rows = r.storage.prefix_iter_cf(schema::cf::CHANNEL_META_MSGS, &CID.to_be_bytes(), 100).unwrap();
        assert!(rows.iter().any(|(k, _)| k[8] == MessageType::ChannelAddModerator as u8));
        assert!(rows.iter().any(|(k, _)| k[8] == MessageType::ChannelRemoveModerator as u8));
    }

    // ---- Cross-node ----

    #[test]
    fn cross_node_moderator_invite_join_converges() {
        let (host, _d1) = enforced();
        let (remote, _d2) = enforced();
        let (c, m, j) = (wallet(), wallet(), wallet());
        for r in [&host, &remote] {
            make_channel(r, CID, &c.addr, 2);
            register(r, &m.addr);
        }
        // Host knows the moderator; the remote node never saw the grant.
        let g = grant(&c, CID, &m.addr, now() - 10_000);
        assert!(accepted(&host.process_message(&g)));
        let inv = invite(&m, CID, &j.addr, now() - 5_000, None, Some(g));
        for r in [&host, &remote] {
            assert!(accepted(&r.process_message(&inv)), "invite must be accepted on both nodes");
        }
        let jn = join(&j, CID, Some(inv), now());
        for r in [&host, &remote] {
            assert!(accepted(&r.process_message(&jn)));
            assert!(is_member(r, CID, &j.addr));
        }
        // A proofless join is rejected identically on both.
        let x = wallet();
        let bad = join(&x, CID, None, now());
        for r in [&host, &remote] {
            rejected_with(r.process_message(&bad), "private channel: invite proof required");
        }
    }

    // ---- Audit-fix round (0.140.0): mainnet, federate creator path, rechecks ----

    fn mainnet_router(activation: u64) -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        let cfg = crate::config::ChannelVerifyConfig {
            private_join_proof_activation_ms: activation,
            ..Default::default()
        };
        (
            MessageRouter::new(
                storage,
                identity,
                None,
                "mainnet".to_string(),
                usize::MAX,
                std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()),
                crate::config::RateLimitsConfig::default(),
            )
            .with_channel_verify_config(cfg),
            dir,
        )
    }

    #[test]
    fn mainnet_ignores_a_nonzero_activation_and_requires_proof() {
        // Security audit B1: a mainnet node on a default/testnet-copied
        // config must not accept proofless private joins.
        let (r, _d) = mainnet_router(FAR_FUTURE);
        assert_eq!(r.join_proof_activation_ms(), 0);
        let j = wallet();
        assert_eq!(
            r.verify_private_join(CID, &j.addr, 1_000, None, true).unwrap_err(),
            "private channel: invite proof required",
            "even a backdated sync join is refused on mainnet"
        );
        // Control: the same config on testnet grandfathers it.
        let (t, _d2) = router_with_activation(FAR_FUTURE);
        assert!(t.verify_private_join(CID, &j.addr, 1_000, None, true).is_ok());
    }

    /// A signed private ChannelCreate whose id matches its derivation.
    fn derived_create(w: &W, slug: &str, ts: u64, forge: bool) -> (Vec<u8>, u64) {
        const M: u64 = (1u64 << 53) - 1;
        let mut t = ts;
        let cid = loop {
            let h = crypto::keccak256(format!("{}{}{}", w.addr, slug, t).as_bytes());
            let id = u64::from_be_bytes(h[..8].try_into().unwrap()) % M;
            if id > PRIVATE_CHANNEL_ID_FLOOR {
                break id;
            }
            t += 1;
        };
        let cid = if forge { cid + 1 } else { cid };
        let p = ChannelCreatePayload {
            channel_id: cid,
            slug: slug.to_string(),
            channel_type: ChannelType::Private,
            display_name: None,
            description: None,
            content_rating: Default::default(),
            moderation: ModerationPolicy { admins: vec![], rules: None },
            encryption_enabled: None,
            history_visibility: None,
            id_derivation_ts: Some(t),
        };
        (sign(w, MessageType::ChannelCreate, rmp_serde::to_vec_named(&p).unwrap(), t), cid)
    }

    #[test]
    fn federate_bootstrap_gate_creator_path_and_invites() {
        let (r, _d) = enforced();
        let (c, j, x, m) = (wallet(), wallet(), wallet(), wallet());
        let (create, cid) = derived_create(&c, "secret-room", now() - 60_000, false);
        // Creator federating their own channel: no invite needed.
        assert_eq!(r.federate_bootstrap_gate(&create, cid, &c.addr, now(), None), Ok(()));
        // Someone else without an invite: denied with the stable reason.
        assert_eq!(
            r.federate_bootstrap_gate(&create, cid, &j.addr, now(), None),
            Err(BootstrapGateError::Denied("private channel: invite proof required".into()))
        );
        // A creator-signed invite: accepted.
        let inv = invite(&c, CID, &j.addr, now() - 1_000, None, None);
        let inv_ok = invite(&c, cid, &j.addr, now() - 1_000, None, None);
        assert_eq!(r.federate_bootstrap_gate(&create, cid, &j.addr, now(), Some(&inv_ok)), Ok(()));
        // Invite for another channel: denied.
        assert!(matches!(
            r.federate_bootstrap_gate(&create, cid, &j.addr, now(), Some(&inv)),
            Err(BootstrapGateError::Denied(_))
        ));
        // Self-signed "invite" by a non-moderator: passes rules 4-7 (so it
        // gets past the pre-fetch gate) but is denied here, rule 8.
        let selfish = invite(&x, cid, &x.addr, now() - 1_000, None, None);
        assert!(r.federate_prefetch_gate(cid, &x.addr, now(), Some(&selfish)).is_ok());
        assert_eq!(
            r.federate_bootstrap_gate(&create, cid, &x.addr, now(), Some(&selfish)),
            Err(BootstrapGateError::Denied("private channel: inviter is not creator or moderator".into()))
        );
        // Moderator invite with a creator grant: accepted.
        let g = grant(&c, cid, &m.addr, now() - 5_000);
        let mod_inv = invite(&m, cid, &j.addr, now() - 1_000, None, Some(g));
        assert_eq!(r.federate_bootstrap_gate(&create, cid, &j.addr, now(), Some(&mod_inv)), Ok(()));
        // Nothing was stored by any of these decisions.
        assert!(!r.storage.exists_cf(schema::cf::CHANNELS, &cid.to_be_bytes()).unwrap());
        assert!(!is_member(&r, cid, &c.addr));
    }

    #[test]
    fn federate_bootstrap_gate_rejects_forged_derivation_even_when_policy_is_off() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        let cfg = crate::config::ChannelVerifyConfig {
            require_private_id_derivation: false,
            private_join_proof_activation_ms: 0,
            ..Default::default()
        };
        let r = MessageRouter::new(
            storage,
            identity,
            None,
            "testnet".to_string(),
            usize::MAX,
            std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()),
            crate::config::RateLimitsConfig::default(),
        )
        .with_channel_verify_config(cfg);
        let c = wallet();
        let (forged, cid) = derived_create(&c, "secret-room", now() - 60_000, true);
        assert!(matches!(
            r.federate_bootstrap_gate(&forged, cid, &c.addr, now(), None),
            Err(BootstrapGateError::BadBootstrap(_))
        ));
        // Wrong channel id asked for, and garbage bytes: also bad bootstrap.
        let (good, gcid) = derived_create(&c, "other-room", now() - 60_000, false);
        assert!(matches!(
            r.federate_bootstrap_gate(&good, gcid + 7, &c.addr, now(), None),
            Err(BootstrapGateError::BadBootstrap(_))
        ));
        assert!(matches!(
            r.federate_bootstrap_gate(b"junk", gcid, &c.addr, now(), None),
            Err(BootstrapGateError::BadBootstrap(_))
        ));
    }

    #[test]
    fn apply_time_recheck_catches_a_ban_landing_after_authorization() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let inv = invite(&c, CID, &j.addr, now() - 1_000, None, None);
        let v = r.verify_private_join(CID, &j.addr, now(), Some(&inv), false).unwrap();
        // Ban lands between the gate and the insert. Dated BEFORE the
        // invite, so only the active-ban re-check (not the removal cutoff)
        // can catch it.
        assert!(accepted(&r.process_message(&ban(&c, CID, &j.addr, now() - 5_000))));
        assert!(!r.federate_add_member(CID, &j.addr, now(), &v).unwrap());
        assert!(!is_member(&r, CID, &j.addr));
    }

    #[test]
    fn apply_time_recheck_catches_a_demotion_landing_after_authorization() {
        let (r, _d) = enforced();
        let (c, m, j) = (wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let g = grant(&c, CID, &m.addr, now() - 50_000);
        let inv = invite(&m, CID, &j.addr, now() - 10_000, None, Some(g));
        let join_ts = now();
        let v = r.verify_private_join(CID, &j.addr, join_ts, Some(&inv), false).unwrap();
        assert_eq!(v.verdict, JoinVerdict::Invited);
        // Demotion lands between the gate and the insert.
        r.storage
            .raise_channel_role_watermark(CID, schema::role_watermark_kind::MODERATOR_REMOVED, &m.addr, join_ts - 1)
            .unwrap();
        assert!(!r.federate_add_member(CID, &j.addr, join_ts, &v).unwrap());
        assert!(!is_member(&r, CID, &j.addr));
        // Control: without the demotion the same facts are added.
        let (r2, _d2) = enforced();
        make_channel(&r2, CID, &c.addr, 2);
        let v2 = r2.verify_private_join(CID, &j.addr, join_ts, Some(&inv), false).unwrap();
        assert!(r2.federate_add_member(CID, &j.addr, join_ts, &v2).unwrap());
    }

    #[test]
    fn federate_add_member_reports_not_added_after_a_kick_and_unknown_channel_is_never_applied() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let inv = invite(&c, CID, &j.addr, now() - 10_000, None, None);
        let v = r.verify_private_join(CID, &j.addr, now(), Some(&inv), false).unwrap();
        assert!(accepted(&r.process_message(&kick(&c, CID, &j.addr, now() - 1_000))));
        assert!(!r.federate_add_member(CID, &j.addr, now(), &v).unwrap());
        // A verdict reached while the channel was unknown is never applied,
        // even if the row appears before the insert.
        let (r2, _d2) = enforced();
        let inv2 = invite(&c, CID, &j.addr, now() - 1_000, None, None);
        let v2 = r2.verify_private_join(CID, &j.addr, now(), Some(&inv2), false).unwrap();
        assert_eq!(v2.verdict, JoinVerdict::InvitedUnknownChannel);
        make_channel(&r2, CID, &c.addr, 2);
        assert!(!r2.federate_add_member(CID, &j.addr, now(), &v2).unwrap());
        assert!(!is_member(&r2, CID, &j.addr));
    }

    #[test]
    fn local_moderator_fallback_requires_the_listing_to_cover_the_invite() {
        // Security audit N3: an invite signed while the moderator was not
        // (yet / no longer) a moderator must not become valid through a
        // later re-promotion.
        let (r, _d) = enforced();
        let (c, m, j, k, l) = (wallet(), wallet(), wallet(), wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let key = schema::encode_channel_moderator_key(CID, &m.addr);
        let invite_ts = now() - 20_000;
        // Record from a grant dated AFTER the invite: rejected.
        r.storage
            .put_cf(schema::cf::CHANNEL_MODERATORS, &key, serde_json::json!({"grant_ts": invite_ts + 5}).to_string().as_bytes())
            .unwrap();
        let inv = invite(&m, CID, &j.addr, invite_ts, None, None);
        rejected_with(r.process_message(&join(&j, CID, Some(inv), now())), "inviter is not creator or moderator");
        // Record from a grant dated BEFORE the invite: accepted.
        r.storage
            .put_cf(schema::cf::CHANNEL_MODERATORS, &key, serde_json::json!({"grant_ts": invite_ts - 5}).to_string().as_bytes())
            .unwrap();
        let inv = invite(&m, CID, &k.addr, invite_ts, None, None);
        assert!(accepted(&r.process_message(&join(&k, CID, Some(inv), now()))));
        // Legacy record (no grant_ts) + a demotion at/after the invite: rejected.
        r.storage.put_cf(schema::cf::CHANNEL_MODERATORS, &key, b"{}").unwrap();
        r.storage
            .raise_channel_role_watermark(CID, schema::role_watermark_kind::MODERATOR_REMOVED, &m.addr, invite_ts)
            .unwrap();
        let inv = invite(&m, CID, &l.addr, invite_ts, None, None);
        rejected_with(r.process_message(&join(&l, CID, Some(inv), now())), "inviter is not creator or moderator");
    }

    #[test]
    fn positional_channel_invite_payloads_decode() {
        // 3-element (pre-0.140.0 sdk-rust) and 5-element positional forms.
        let three = rmp_serde::to_vec(&(CID, "klv1t".to_string(), Option::<String>::None)).unwrap();
        let p: ChannelInvitePayload = rmp_serde::from_slice(&three).unwrap();
        assert_eq!((p.channel_id, p.expires_at, p.inviter_grant), (CID, None, None));
        let five = rmp_serde::to_vec(&(
            CID,
            "klv1t".to_string(),
            Some("https://h.example".to_string()),
            Some(99u64),
            Some(vec![7u8, 8]),
        ))
        .unwrap();
        let p: ChannelInvitePayload = rmp_serde::from_slice(&five).unwrap();
        assert_eq!(p.expires_at, Some(99));
        assert_eq!(p.inviter_grant, Some(vec![7, 8]));
        // A 4-element form (grant omitted, expires_at nil) also decodes.
        let four = rmp_serde::to_vec(&(CID, "klv1t".to_string(), Option::<String>::None, Option::<u64>::None)).unwrap();
        let p: ChannelInvitePayload = rmp_serde::from_slice(&four).unwrap();
        assert_eq!(p.inviter_grant, None);
    }

    #[test]
    fn backfill_channel_meta_v3_indexes_moderator_messages() {
        let (r, _d) = enforced();
        let c = wallet();
        let m = wallet();
        let add = grant(&c, CID, &m.addr, 10_000);
        let rm = remove_mod(&c, CID, &m.addr, 20_000);
        for raw in [&add, &rm] {
            let env: Envelope = rmp_serde::from_slice(raw).unwrap();
            r.storage.store_message(&env.msg_id, raw).unwrap();
        }
        assert!(r.storage.prefix_iter_cf(schema::cf::CHANNEL_META_MSGS, &CID.to_be_bytes(), 10).unwrap().is_empty());
        r.storage.backfill_channel_meta().unwrap();
        let rows = r.storage.prefix_iter_cf(schema::cf::CHANNEL_META_MSGS, &CID.to_be_bytes(), 10).unwrap();
        assert!(rows.iter().any(|(k, _)| k[8] == MessageType::ChannelAddModerator as u8));
        assert!(rows.iter().any(|(k, _)| k[8] == MessageType::ChannelRemoveModerator as u8));
        assert_eq!(r.storage.get_stat(schema::state_keys::CHANNEL_META_INDEXED_V3).unwrap(), 1);
    }

    // ---- Wire fixtures ----

    /// Hand-built msgpack, as `@msgpack/msgpack` emits it: a MAP with a
    /// `bin` value for `invite`.
    fn js_map_join_payload(cid: u64, invite: &[u8]) -> Vec<u8> {
        let mut b = vec![0x82];
        b.push(0xa0 | 10);
        b.extend_from_slice(b"channel_id");
        b.push(0xcf);
        b.extend_from_slice(&cid.to_be_bytes());
        b.push(0xa0 | 6);
        b.extend_from_slice(b"invite");
        b.push(0xc5);
        b.extend_from_slice(&(invite.len() as u16).to_be_bytes());
        b.extend_from_slice(invite);
        b
    }

    #[test]
    fn js_map_with_bin_join_payload_decodes_and_is_accepted() {
        let (r, _d) = enforced();
        let (c, j) = (wallet(), wallet());
        make_channel(&r, CID, &c.addr, 2);
        let inv = invite(&c, CID, &j.addr, now() - 1_000, None, None);
        let payload = js_map_join_payload(CID, &inv);
        let decoded: ChannelJoinPayload = rmp_serde::from_slice(&payload).unwrap();
        assert_eq!(decoded.channel_id, CID);
        assert_eq!(decoded.invite.as_deref(), Some(inv.as_slice()));
        let raw = sign(&j, MessageType::ChannelJoin, payload, now());
        assert!(accepted(&r.process_message(&raw)));
        assert!(is_member(&r, CID, &j.addr));
    }

    #[test]
    fn positional_array_join_payloads_decode() {
        // sdk-rust form: [channel_id] (pre-0.140.0) and [channel_id, invite].
        let one = rmp_serde::to_vec(&(CID,)).unwrap();
        let p: ChannelJoinPayload = rmp_serde::from_slice(&one).unwrap();
        assert_eq!((p.channel_id, p.invite), (CID, None));
        let two = rmp_serde::to_vec(&(CID, vec![1u8, 2, 3])).unwrap();
        let p: ChannelJoinPayload = rmp_serde::from_slice(&two).unwrap();
        assert_eq!(p.invite, Some(vec![1, 2, 3]));
        // A proofless map join still encodes exactly like before (no key).
        let legacy = rmp_serde::to_vec_named(&ChannelJoinPayload { channel_id: CID, invite: None }).unwrap();
        assert_eq!(legacy[0], 0x81);
    }
}

#[cfg(test)]
mod internal_error_reason_tests {
    //! Round-4 audit 9b: infrastructure failures never put RocksDB/anyhow
    //! text into a rejection reason (reasons reach HTTP clients), and the
    //! step-7 wrappers keep the internal reason EXACT so the API maps it to
    //! a generic 500.
    use super::*;

    #[test]
    fn internal_error_returns_the_fixed_reason_without_detail() {
        let r = internal_error("storage", "IO error: /var/lib/ogmara/db/000123.sst: corruption");
        assert_eq!(r, INTERNAL_ERROR_REASON);
        assert!(!r.contains("IO error") && !r.contains("/var/lib"));
    }

    #[test]
    fn wrappers_pass_the_internal_reason_through_unprefixed() {
        assert_eq!(wrap_rejection("unauthorized", INTERNAL_ERROR_REASON.to_string()), INTERNAL_ERROR_REASON);
        assert_eq!(
            wrap_rejection("unauthorized", "only the channel creator can manage moderators".into()),
            "unauthorized: only the channel creator can manage moderators"
        );
    }
}

#[cfg(test)]
mod key_envelope_rate_limit_tests {
    //! l2-node 0.143.0: `retry_after_ms` arithmetic of `rate_limit_check`.
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn retry_after_is_window_end_plus_one() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        let r = MessageRouter::new(
            storage,
            identity,
            None,
            "testnet".into(),
            usize::MAX,
            Arc::new(crate::metrics::counters::NetworkCounters::new()),
            crate::config::RateLimitsConfig::default(),
        );
        let t0 = 1_000_000u64;
        for _ in 0..240 {
            assert_eq!(r.rate_limit_check("klv1a", RateCategory::KeyEnvelope, false, t0), None);
        }
        // Window [t0, t0+60000] resets only once now - t0 > 60000.
        assert_eq!(r.rate_limit_check("klv1a", RateCategory::KeyEnvelope, false, t0), Some(60_001));
        assert_eq!(r.rate_limit_check("klv1a", RateCategory::KeyEnvelope, false, t0 + 60_000), Some(1));
        assert_eq!(r.rate_limit_check("klv1a", RateCategory::KeyEnvelope, false, t0 + 60_001), None);
        // DM-scope 0x61 shares the category (it moved off `Other`).
        assert_eq!(RateCategory::from_msg_type(MessageType::ChannelKeyEnvelope), RateCategory::KeyEnvelope);
    }

    fn test_router() -> (MessageRouter, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        (
            MessageRouter::new(
                storage,
                identity,
                None,
                "testnet".into(),
                usize::MAX,
                Arc::new(crate::metrics::counters::NetworkCounters::new()),
                crate::config::RateLimitsConfig::default(),
            ),
            dir,
        )
    }

    /// Round-3 N-b / round-4 N6: per-(wallet, scope) windows live exactly
    /// their 60 s window and are pruned on a 60 s schedule; ordinary buckets
    /// keep the 1-day retention.
    #[test]
    fn scope_buckets_expire_after_their_own_window() {
        let (r, _d) = test_router();
        let now = 10_000_000u64;
        let old = || RateLimitEntry {
            burst_count: 1,
            burst_window_start: now - 61_000,
            sustained_count: 1,
            sustained_window_start: now - 61_000,
        };
        r.local_key_scope_windows.insert("klv1a:00".into(), old());
        r.local_key_scope_windows.insert("klv1b:00".into(), RateLimitEntry {
            burst_count: 1,
            burst_window_start: now - 1_000,
            sustained_count: 1,
            sustained_window_start: now - 1_000,
        });
        r.rate_limits.insert("klv1a:KeyEnvelope".into(), old());
        r.prune_key_envelope_buckets(now);
        assert!(!r.local_key_scope_windows.contains_key("klv1a:00"), "expired scope window pruned");
        assert!(r.local_key_scope_windows.contains_key("klv1b:00"), "live window kept");
        assert!(r.rate_limits.contains_key("klv1a:KeyEnvelope"), "wallet bucket untouched");
        // A second prune within 60 s is skipped (schedule), the next one runs.
        r.local_key_scope_windows.insert("klv1c:00".into(), old());
        r.prune_key_envelope_buckets(now + 1_000);
        assert!(r.local_key_scope_windows.contains_key("klv1c:00"));
        r.prune_key_envelope_buckets(now + 61_000);
        assert!(!r.local_key_scope_windows.contains_key("klv1c:00"));
    }

    /// Round-5 B1: the unstored-key seen-cache is bounded (oldest first)
    /// and expires after its TTL.
    #[test]
    fn unstored_key_cache_is_bounded_and_expires() {
        let mut c = UnstoredKeyCache::default();
        let id = |n: u32| {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&n.to_be_bytes());
            a
        };
        for n in 0..(UNSTORED_KEY_CACHE_MAX as u32 + 10) {
            c.insert(id(n), UnstoredOutcome::AlreadyPresent, 1_000);
        }
        assert_eq!(c.len(), UNSTORED_KEY_CACHE_MAX);
        assert!(c.lookup(&id(0), 1_000).is_none(), "oldest evicted first");
        assert!(c.lookup(&id(UNSTORED_KEY_CACHE_MAX as u32 + 9), 1_000).is_some());
        // TTL: still there at exactly the TTL, gone after it.
        assert!(c.lookup(&id(50), 1_000 + UNSTORED_KEY_CACHE_TTL_MS).is_some());
        assert!(c.lookup(&id(50), 1_001 + UNSTORED_KEY_CACHE_TTL_MS).is_none());
        assert_eq!(c.len(), 0);
    }

    /// Round-5 N1: a full gossip-bucket map still admits wallets it already
    /// tracks; only NEW keys are refused.
    #[test]
    fn full_gossip_bucket_map_still_admits_known_keys() {
        let (r, _d) = test_router();
        let now = 5_000_000u64;
        // Fill to the cap with non-prunable (drained) buckets.
        for n in 0..GOSSIP_KEY_BUCKETS_MAX {
            r.gossip_key_buckets.insert(format!("klv1fill{n}"), TokenBucket { tokens: 0.0, last_ms: now });
        }
        r.gossip_key_buckets.insert("klv1known".into(), TokenBucket { tokens: 10.0, last_ms: now });
        r.gossip_key_buckets.remove("klv1fill0");
        let env = Envelope {
            version: 1,
            msg_type: MessageType::ChannelKeyEnvelope,
            msg_id: [0; 32],
            author: "x".into(),
            timestamp: 1,
            lamport_ts: 0,
            payload: vec![],
            signature: vec![0; 64],
            relay_path: vec![],
        };
        assert!(r.gossip_key_envelope_allowed(&env, "klv1known", now), "known key admitted at the cap");
        assert!(!r.gossip_key_envelope_allowed(&env, "klv1new", now), "new key refused at the cap");
    }

    /// Round-6 F6: pin the sizes behind the seen-cache memory estimate.
    #[test]
    fn unstored_cache_entry_sizes() {
        assert!(std::mem::size_of::<UnstoredOutcome>() <= 24, "{}", std::mem::size_of::<UnstoredOutcome>());
        assert!(std::mem::size_of::<KeyConflictInfo>() <= 160, "{}", std::mem::size_of::<KeyConflictInfo>());
        assert!(std::mem::size_of::<([u8; 32], u64)>() <= 40);
    }

    /// Round-6 M9: the forced prune at the bucket-map cap runs at most once
    /// per second.
    #[test]
    fn forced_bucket_prune_is_gated_to_once_per_second() {
        let (r, _d) = test_router();
        let now = 9_000_000u64;
        // Suppress the 60 s lazy prune so only the forced one can run.
        r.key_bucket_last_prune_ms.store(now, std::sync::atomic::Ordering::Relaxed);
        let fill = |r: &MessageRouter, at: u64| {
            r.gossip_key_buckets.clear();
            // Fully refilled buckets: prunable.
            for n in 0..GOSSIP_KEY_BUCKETS_MAX {
                r.gossip_key_buckets.insert(format!("klv1f{n}"), TokenBucket { tokens: 720.0, last_ms: at });
            }
        };
        let env = Envelope {
            version: 1,
            msg_type: MessageType::ChannelKeyEnvelope,
            msg_id: [0; 32],
            author: "x".into(),
            timestamp: 1,
            lamport_ts: 0,
            payload: vec![],
            signature: vec![0; 64],
            relay_path: vec![],
        };
        fill(&r, now);
        assert!(r.gossip_key_envelope_allowed(&env, "klv1new1", now), "forced prune made room");
        fill(&r, now);
        assert!(!r.gossip_key_envelope_allowed(&env, "klv1new2", now + 500), "second forced prune within 1 s is skipped");
        assert!(r.gossip_key_envelope_allowed(&env, "klv1new2", now + 1_000), "allowed again after 1 s");
    }

    /// Round-4 N4: peeks and refusals never create entries.
    #[test]
    fn refused_and_peeked_checks_create_no_entries() {
        let (r, _d) = test_router();
        let limits = RateLimits::flat(1, 60_000);
        assert_eq!(MessageRouter::window_check(&r.rate_limits, "k".into(), limits, 1, false), None);
        assert!(r.rate_limits.is_empty(), "peek creates nothing");
        assert_eq!(MessageRouter::window_check(&r.rate_limits, "k".into(), limits, 1, true), None);
        assert_eq!(MessageRouter::window_check(&r.rate_limits, "k".into(), limits, 2, true), Some(60_000));
        assert_eq!(r.rate_limits.get("k").map(|e| e.burst_count), Some(1), "refusal did not count");
        assert_eq!(MessageRouter::window_check(&r.rate_limits, "k".into(), limits, 60_002, true), None, "reset after > window");
    }

    /// Round-4 audit W1a: gossip token buckets admit a home node's maximum
    /// (2 x its fixed-window limit in a 60 s span) and refuse a flood.
    #[test]
    fn gossip_token_buckets_admit_two_windows_and_refuse_floods() {
        let (r, _d) = test_router();
        let scope = [7u8; 32];
        let env = |i: u32| {
            let p = ChannelKeyEnvelopePayload {
                key_scope: scope,
                scope_kind: crate::messages::types::key_scope_kind::CHANNEL,
                epoch: 1,
                target: "klv1t".into(),
                device_id: format!("{:064x}", i),
                peer: None,
                channel_id: Some(1),
                eph_pub: [1; 32],
                nonce: [1; 24],
                wrapped: vec![1; 48],
                key_commitment: Some([1; 32]),
                key_ts: Some(1),
            };
            Envelope {
                version: 1,
                msg_type: MessageType::ChannelKeyEnvelope,
                msg_id: [0; 32],
                author: "klv1a".into(),
                timestamp: 1,
                lamport_ts: 0,
                payload: rmp_serde::to_vec_named(&p).unwrap(),
                signature: vec![0; 64],
                relay_path: vec![],
            }
        };
        let t0 = 1_000_000u64;
        // Home node: 60 at the end of one window + 60 at the start of the
        // next, all within ~1 s on the wire → 120 per scope must pass.
        for i in 0..120u32 {
            assert!(r.gossip_key_envelope_allowed(&env(i), "klv1a", t0 + i as u64), "#{i}");
        }
        // 180 burst capacity: 60 more pass, then the scope bucket refuses.
        for i in 120..180u32 {
            assert!(r.gossip_key_envelope_allowed(&env(i), "klv1a", t0 + 200));
        }
        assert!(!r.gossip_key_envelope_allowed(&env(999), "klv1a", t0 + 200), "flood refused");
        // Refill 1/s.
        assert!(r.gossip_key_envelope_allowed(&env(1000), "klv1a", t0 + 1_300));
        // Per wallet: 720 burst across scopes, then refused.
        let (r, _d) = test_router();
        let mut ok = 0;
        for i in 0..800u32 {
            let mut e = env(i);
            let mut p: ChannelKeyEnvelopePayload = rmp_serde::from_slice(&e.payload).unwrap();
            p.key_scope = [(i % 8) as u8; 32];
            e.payload = rmp_serde::to_vec_named(&p).unwrap();
            if r.gossip_key_envelope_allowed(&e, "klv1a", t0) {
                ok += 1;
            }
        }
        assert_eq!(ok, 720);
        // Refused attempts created no extra entries: 1 wallet + 8 scopes.
        assert_eq!(r.gossip_key_buckets.len(), 9);
    }
}
