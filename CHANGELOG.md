# Changelog

All notable changes to the Ogmara L2 node will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.12.3] - 2026-04-04

### Fixed

- DM unread counts now exclude the requesting user's own messages (same fix as channels in v0.11.4)

## [0.12.2] - 2026-04-04

### Changed

- Private channel join now allowed via invite links by default — knowing the channel ID (via shared link) is treated as proof of invitation. Owners can disable this with `invite_links_disabled: true` in channel metadata

## [0.12.1] - 2026-04-04

### Fixed

- `GET /api/v1/channels/:id` now returns limited channel info (name, slug, description, type, member count) for private channels when the caller is not a member, instead of 404 — enables invite/join page to display channel details

## [0.12.0] - 2026-04-04

### Added
- **Notification engine wired into node startup** — `NotificationEngine` is now
  created during `Node::run()` and connected to both the GossipSub message pipeline
  and the REST API message submission endpoint
- Mention detection for `ChatMessage` and `NewsComment` — parses the `mentions`
  field and delivers notifications to locally connected users
- Push gateway integration — when `[push_gateway]` is configured, notifications
  are forwarded via HTTP POST to the push gateway with correct `PushTrigger` payload
- WebSocket user tracking — authenticated WS clients are registered/unregistered
  with the notification engine for real-time mention matching
- `RouteResult::Accepted` now carries `raw_bytes` for downstream processing
  without re-deserialization
- `NotificationEngine` uses `Arc<RwLock<HashSet>>` for thread-safe local user tracking
- `AppState::with_broadcast()` constructor for sharing the broadcast channel
  between the notification engine and WebSocket layer

## [0.11.6] - 2026-04-04

### Fixed

- User profile endpoint now returns `follower_count` and `following_count` from cached counts

## [0.11.5] - 2026-04-04

### Fixed

- Edited messages now return the updated content — `enrich_message_json` fetches the latest edit envelope and replaces the original payload with `EditPayload.content`

## [0.11.4] - 2026-04-04

### Added

- `GET /api/v1/settings` endpoint — returns encrypted settings with `encrypted_settings`, `nonce`, and `key_epoch` fields

### Fixed

- Settings sync now stores full payload (nonce + key_epoch) instead of just ciphertext, so clients can decrypt
- Unread counts no longer include the requesting user's own messages

## [0.11.3] - 2026-04-04

### Fixed

- Chat message reactions now included in API responses — `enrich_message_json` adds `reactions` field with emoji counts from `CHAT_REACTION_COUNTS` storage

## [0.11.2] - 2026-04-04

### Added

- **Self-entry in `/api/v1/network/nodes`**: Node now includes itself as the first entry in the node list with real data (node_id, channels, user_count, anchor_status) instead of relying solely on peer announcements
- **`NodeAnnouncement` persistence**: `NodeAnnouncement` (0xE0) messages are now stored in the `PEER_DIRECTORY` column family, populating the network node list from gossip
- **`public_url` config option**: New `[api]` config field to advertise the node's public API endpoint in the network node list

### Security

- **NodeAnnouncement identity verification**: Claimed `node_id` in announcements is verified against the envelope author's public key (`Base58(SHA-256(pubkey)[:20])`) to prevent spoofing
- **Announcement payload validation**: `api_endpoint` validated as HTTP/HTTPS URL (max 256 bytes), `channels` list capped at 10,000 entries
- **Peer directory size cap**: Maximum 10,000 entries; new nodes rejected when at capacity (existing nodes can still update)
- **TTL filtering**: Stale peer entries (past `last_seen + ttl_seconds`) excluded from API response

## [0.11.1] - 2026-04-02

### Fixed

- **ChannelUpdate not applied**: ChannelUpdate envelopes were authorized and validated but never written to storage — channel edits (name, description, logo, banner, website, tags) are now merged into existing channel metadata
- **Chain scanner overwrites L2 metadata**: On-chain `channelCreated` events were overwriting the full channel record with `display_name: None` and `description: None`, erasing the L2-provided values. The scanner now preserves existing `display_name`, `description`, and `member_count` when re-processing a known channel

## [0.11.0] - 2026-04-02

### Added
- **9 new column families** — `deletion_markers`, `edit_history`, `chat_reactions`,
  `chat_reaction_counts`, `reports`, `counter_votes`, `channel_mutes`,
  `settings_sync`, `notifications` with full key encoders and storage helpers.
- **Moderation routing** — `Report` (0x40), `CounterVote` (0x41), and `ChannelMute`
  (0x42) messages now stored and indexed. Reports and counter-votes tracked per
  target. Mutes stored with expiration support.
- **Account/Device routing** — `SettingsSync` (0x33) stores encrypted settings
  per user. `DeviceRevocation` (0x32) revokes device keys via identity resolver.
  `DeletionRequest` (0x50) soft-deletes single messages or all user news posts.
- **5 new API endpoints:**
  - `GET /api/v1/users/{address}/posts` — user's news posts with enrichment
  - `GET /api/v1/notifications` — persisted mention notifications (30-day retention)
  - `GET /api/v1/moderation/reports?target=<hex>` — transparency log with score
  - `GET /api/v1/moderation/user/{address}` — reputation profile with trust score
  - `GET /api/v1/account/export` — downloadable text file with all user data
- **Notification persistence** — NotificationEngine now stores notifications in
  the NOTIFICATIONS CF for API retrieval, not just WebSocket broadcast.
- **`create_channel` handler** — `POST /api/v1/channels` now returns
  `{ "ok": true, "msg_id": "...", "channel_id": N }` instead of generic post_message.
- **`enrich_message_json` helper** — centralized deletion/edit status enrichment
  applied to all message-returning endpoints.
- **Mute enforcement in API** — `get_channel_messages` adds `"muted": true` flag
  on messages from muted authors (content still delivered, clients hide by default).

### Changed
- All message-returning endpoints now check `DELETION_MARKERS` and `EDIT_HISTORY`,
  adding `"deleted": true` / `"edited": true` fields and blanking deleted payloads.
- Payload validators wired for CounterVote, ChannelMute, SettingsSync,
  DeviceRevocation, and DeletionRequest message types.

### Removed
- Stale TODO comment about ChannelDelete in router.rs (already implemented via API).

## [0.10.0] - 2026-04-02

### Added
- **Edit/Delete message routing (Phase 2)** — full routing pipeline for 8
  message types: ChatEdit, ChatDelete, ChatReaction, DirectMessageEdit,
  DirectMessageDelete, DirectMessageReaction, NewsEdit, NewsDelete.
- **`authorize_edit_delete` method** — verifies original message authorship,
  enforces 30-minute edit window, and requires registered user for NewsEdit.
- **`extract_channel_id` for ChatEdit/ChatDelete** — enables channel-scoped
  ban enforcement for edit and delete operations.
- **`update_indexes` arms** — stores edit history (EDIT_HISTORY CF), deletion
  markers (DELETION_MARKERS CF), and chat reactions (CHAT_REACTIONS CF). DM
  reactions are encrypted and intentionally not indexed.
- **Payload validators** — `validate_chat_edit`, `validate_chat_delete`,
  `validate_dm_edit`, `validate_dm_delete`, `validate_news_edit`,
  `validate_news_delete` with type-specific length limits.
- **Type-specific validation dispatch** — Edit and Delete payloads now route
  to the correct validator based on `msg_type` (chat vs DM vs news limits).

## [0.9.7] - 2026-04-02

### Fixed
- **Device-signed registration rejected unnecessarily** — removed USERS CF
  existence check that blocked device-signed claims for wallets not yet
  registered on-chain. The device auth check (caller = device) is sufficient
  security. Added server-side logging for registration success/failure to
  aid debugging.

## [0.9.6] - 2026-04-02

### Added
- **Device-signed registration fallback** — `POST /api/v1/devices/register`
  now accepts device-signed claims (in addition to wallet-signed). When the
  wallet signature fails verification, the server checks if the claim was
  signed by the device key itself. Requires: caller must be the device (auth
  headers), and wallet must be a registered on-chain user (USERS CF).
  Enables K5 mobile browser device registration where `signMessage` is
  unavailable.

## [0.9.5] - 2026-04-02

### Fixed
- **Startup migration: backfill DEVICE_WALLET_MAP from DELEGATIONS** — v0.9.4
  fixed the scanner for new delegations, but existing delegations (already
  processed before the fix) were never backfilled. This one-time startup
  migration reads all active entries from `DELEGATIONS`, converts hex pubkeys
  to klv1 addresses, and creates the missing `DEVICE_WALLET_MAP` + `WALLET_DEVICES`
  entries. Fixes K5 wallet users unable to see private channels, DMs, or
  bookmarks on the web app opened in K5 browser.

## [0.9.4] - 2026-04-02

### Fixed
- **K5 delegation identity resolution broken** — chain scanner stored device
  delegations in `DELEGATIONS` CF but never wrote to `DEVICE_WALLET_MAP`.
  The auth middleware uses `DEVICE_WALLET_MAP` for device → wallet resolution,
  so K5-delegated devices were never resolved to their wallet address. All
  operations (channel access, DMs, unread counts) used the device address
  instead of the wallet address, causing cross-device identity mismatch.
  Scanner now writes both `DEVICE_WALLET_MAP` and `WALLET_DEVICES` entries
  when processing `DeviceDelegated` events.

## [0.9.3] - 2026-04-02

### Security
- **Private channel members/pins leak** — `GET /channels/:id/members` and
  `GET /channels/:id/pins` were fully public endpoints with no access control.
  Anyone could enumerate members and read pinned content of private channels.
  Now gated behind optional auth with `require_channel_access()` check.
- **Unread counts leaked private channels** — `GET /channels/unread` returned
  counts for all channels, revealing private channel IDs and activity to any
  authenticated user. Now filters out private channels the user isn't a member of.

### Changed
- Extracted `is_private_channel()` and `require_channel_access()` helpers to
  centralize the dual-format channel_type check across all endpoints.
- Moved `/channels/:id/members` and `/channels/:id/pins` from public routes
  to optional-auth routes.

## [0.9.2] - 2026-04-02

### Security
- **Router invite check bypassed for L2-created private channels** — the
  `ChannelJoin` authorization only checked `channel_type == 2` (integer), but
  L2-created channels stored it as `"Private"` (string). Users could join
  private channels without an invite. Now checks both forms.

### Fixed
- **channel_type serialization normalized** — router now stores `channel_type`
  as `u8` integer (matching the chain scanner) instead of serde enum string.
- **Startup migration** — one-time migration normalizes existing string
  `channel_type` values (`"Public"`, `"ReadPublic"`, `"Private"`) to integers
  (0, 1, 2) in the `CHANNELS` column family. Runs automatically on first boot.

## [0.9.1] - 2026-04-02

### Fixed
- **Private channel filter bypassed** — `channel_type` is stored as `"Private"`
  (string) by the message router but as `2` (integer) by the chain scanner.
  The privacy check only matched the integer form, so router-created private
  channels passed through the filter. Now checks both representations.

## [0.9.0] - 2026-04-02

### Security
- **Private channels exposed to everyone** — `list_channels`, `get_channel`, and
  `get_channel_messages` returned private channels (type 2) to all users including
  unauthenticated visitors. Private channels are now filtered from listings and
  return 404 for non-members on detail/messages endpoints.

### Added
- **Optional auth middleware** — `optional_auth_middleware` parses auth headers
  when present but passes through without error when missing. Used on public
  endpoints that need to optionally know the caller's identity.
- `check_channel_access()` helper — reusable private channel membership check
  used across list, detail, and messages endpoints.

## [0.8.4] - 2026-04-02

### Fixed
- **Chain scanner missing creator member** — channels created via on-chain events
  did not add the creator to `CHANNEL_MEMBERS` with role `"creator"`. This caused
  the web admin dashboard to be hidden for channel owners. Scanner now adds the
  creator as first member on new channel creation (consistent with message router).

## [0.8.3] - 2026-04-02

### Fixed
- **Channel deletion resurrection bug** — chain scanner unconditionally re-created
  deleted channels from on-chain `ChannelCreated` events. Added `DELETED_CHANNELS`
  tombstone column family; scanner now skips tombstoned channel IDs.
- **Incomplete channel cleanup** — `delete_channel` handler now also removes
  moderator records from `CHANNEL_MODERATORS` and decrements `TOTAL_CHANNELS`.
- **Non-atomic deletion** — tombstone write + channel metadata delete now use
  `WriteBatch` for crash-safe atomicity.
- **Silent error swallowing** — cleanup operations now log warnings on failure
  instead of discarding errors with `let _ =`.

### Added
- `DELETED_CHANNELS` column family — tombstone set (channel_id → deletion timestamp)
  prevents chain scanner from resurrecting intentionally deleted channels.
- `Storage::decrement_stat()` — saturating decrement for u64 stat counters.

## [0.7.0] - 2026-04-01

### Added
- **Direct Messaging endpoints** — full DM retrieval and read-state tracking:
  - `GET /api/v1/dm/conversations` — list DM conversations with peer address,
    last message preview, timestamp, and unread count. Paginated, deduplicated.
  - `GET /api/v1/dm/{address}/messages` — retrieve messages in a DM conversation.
    Computes conversation_id from auth user + path address.
  - `POST /api/v1/dm/{address}/read` — mark DM conversation as read (wall-clock cursor).
  - `GET /api/v1/dm/unread` — get unread DM counts per conversation, capped at 99.
- `DM_READ_STATE` column family — per-user per-conversation read cursors.
- `compute_conversation_id` — Keccak-256 of lexicographically sorted wallet addresses.
- `validate_direct_message` — validates recipient address, sender != recipient,
  content length, and conversation_id correctness.
- DM conversation index writes in `update_indexes` — both sender and recipient
  get entries in `DM_CONVERSATIONS` with the peer address stored as value.

### Fixed
- **DM_MESSAGES prefix extractor** — changed from 8 bytes to 32 bytes to match
  the conversation_id key prefix. Previous value caused incorrect bloom filter behavior.
- **DM_CONVERSATIONS prefix extractor** — changed from 8 bytes to 44 bytes to match
  klv1 bech32 address length.
- Address validation on DM GET endpoints — rejects non-klv1 or wrong-length addresses.

## [0.6.4] - 2026-04-01

### Added
- **Channel read state** — new `CHANNEL_READ_STATE` column family stores
  per-user per-channel read cursors (wall-clock timestamps).
- `POST /api/v1/channels/{channel_id}/read` — mark channel as read.
- `GET /api/v1/channels/unread` — get unread message counts per channel,
  comparing envelope timestamps against the read cursor. Capped at 99.

## [0.6.3] - 2026-04-01

### Fixed
- **Chain scanner no longer wipes profile data** — `UserRegistered` events
  now merge with existing user records, preserving `display_name`,
  `avatar_cid`, and `bio`. Previously, re-scanning a registration block
  would overwrite the entire record with empty profile fields.

## [0.6.2] - 2026-04-01

### Changed
- **API responses now return wallet addresses as author** — `envelope_to_json`
  resolves device keys to wallet addresses via the IdentityResolver. Clients
  always see the canonical wallet identity, never ephemeral device keys.
- `GET /api/v1/users/:address` now resolves device addresses to wallet
  addresses before profile lookup, so lookups by device key find the correct
  profile stored under the wallet address.
- `comment_count` added to `GET /api/v1/news` list response.
- Identity resolution errors are now logged instead of silently ignored.

## [0.6.1] - 2026-04-01

### Added
- **GET /api/v1/news/{msg_id}** — single news post endpoint returning the
  full post with engagement counts and a list of comments, enabling the
  web app's thread view.
- `comment_count` field in the `GET /api/v1/news` list response, allowing
  the feed to show how many comments each post has.

## [0.6.0] - 2026-04-01

### Added
- **Device-to-wallet identity mapping** (Phase 1: storage layer) — enables
  multi-device support where multiple device keys map to a single wallet address.
  New `DEVICE_WALLET_MAP` and `WALLET_DEVICES` column families in RocksDB.
  Storage methods: `register_device`, `revoke_device`, `resolve_wallet`, `list_devices`.
- **IdentityResolver** — in-memory DashMap cache backed by RocksDB for O(1)
  device→wallet resolution on hot paths. Bounded positive-only caching (50K max),
  cache warming at startup, structured logging for data corruption detection.
- 7 unit tests covering registration, resolution, revocation, multi-device,
  cache warming, and idempotent registration.
- **Auth middleware identity resolution** (Phase 2) — after signature verification,
  the middleware resolves device key → wallet address via IdentityResolver.
  `AuthUser` now has `address` (resolved wallet) and `signing_address` (device key).
  Fallback: if no mapping, device key IS the wallet (built-in wallet mode).
  Identity resolver warmed on node startup.
- **Device registration API** (Phase 3) — three new authenticated endpoints:
  `POST /api/v1/devices/register` (wallet-signed claim verification, max 10
  devices per wallet, caller binding), `DELETE /api/v1/devices/{device_address}`
  (wallet-owned revocation, sibling devices can manage each other),
  `GET /api/v1/devices` (list registered devices for authenticated wallet).
- **Message router identity resolution** (Phase 4) — after signature verification,
  `envelope.author` (device key) is resolved to wallet address via IdentityResolver.
  All storage/indexing, rate limiting, ban checks, and authorization use the
  resolved wallet identity. Signature verification still uses the device key.

### Fixed
- Ban expiration check now uses server wall-clock time instead of sender's
  claimed timestamp (prevents ban evasion via timestamp manipulation).
- Removed duplicate `NewsComment` match arm in `update_indexes`.
- Rate limiter counter uses `saturating_add` to prevent u32 overflow.

## [0.5.8] - 2026-04-01

### Changed
- Auth middleware now logs address, method, path, and timestamp on signature
  verification failure for debugging 401 errors

## [0.5.7] - 2026-04-01

### Changed
- **Body size limit** — increased from 1 MB to 10 MB to support media uploads
  (avatar images, attachments). The IPFS client's own size validation still
  enforces the configured max_upload_size_mb limit.

## [0.5.6] - 2026-04-01

### Fixed
- **ProfileUpdate now stored** — `update_indexes` was missing a handler for
  `MessageType::ProfileUpdate`, so profile envelopes were accepted but the
  user record was never updated. Now merges display_name, avatar_cid, and
  bio into the USERS column family. Creates a new user record if none exists
  (unregistered users can set profiles per spec).

## [0.5.5] - 2026-04-01

### Added
- **Media upload endpoint** — `POST /api/v1/media/upload` accepts multipart
  file uploads, validates MIME type and size, and stores on IPFS via Kubo.
  Returns `{ cid, size, mime_type }`. Requires authentication.
- **Media retrieval endpoint** — `GET /api/v1/media/:cid` fetches content
  from IPFS by CID. Public, with immutable cache headers. Detects content
  type from magic bytes (PNG, JPEG, GIF, WebP, PDF).
- IPFS client now stored in AppState and shared with API handlers.

## [0.5.4] - 2026-04-01

### Added
- **Contract address in stats endpoint** — `GET /api/v1/network/stats` now
  returns `contract_address` from the node's `klever.contract_address` config.
  Web/desktop clients use this for on-chain operations (tipping, registration)
  without needing a separate env var.

## [0.5.3] - 2026-04-01

### Added
- **Network field in stats endpoint** — `GET /api/v1/network/stats` now returns
  a `network` field ("testnet" or "mainnet"), derived from the configured Klever
  node URL. Allows clients to display which network the node is connected to.

## [0.5.2] - 2026-03-31

### Added
- **Auto channel membership** — users are automatically added as channel
  members when they send their first ChatMessage to a channel. Previously
  member_count was always 0 because no join mechanism existed.
- **ChannelCreate handler** — `update_indexes` now processes ChannelCreate
  envelopes: stores channel metadata, adds creator as first member,
  increments total_channels counter
- **ChannelJoin/Leave handlers** — adds/removes members from the
  CHANNEL_MEMBERS column family
- **NewsComment indexing** — comments are now indexed in NEWS_COMMENTS
  CF by (post_id, timestamp, msg_id) for future retrieval

### Security
- Channel member check uses `get_cf` before adding to prevent duplicate
  entries (idempotent on repeated messages)

## [0.5.1] - 2026-03-31

### Added

- **Split message counters** — `total_news_messages` and `total_channel_messages`
  fields in `/api/v1/network/stats` response, replacing the single combined
  `total_messages` count (which is still available for backwards compatibility)
- **Counter migration** — existing nodes automatically rebuild the new split
  counters from NEWS_FEED and CHANNEL_MSGS indexes on first startup after
  upgrade, with a `COUNTERS_V2` sentinel to prevent repeated rebuilds

## [0.5.0] - 2026-03-31

### Changed

- **Chain scanner: batch block scanning** — scans 500 blocks per API call
  instead of one-by-one, reducing API requests by 500x and avoiding Klever
  testnet rate limits
- **Chain scanner: use API for block height** — switched from
  `node_url/node/status` (aggressive rate limiting) to
  `api_url/v1.0/block/list?limit=1` for latest block height
- **Chain scanner: parse SC calls from transaction data** — Klever API
  receipts don't contain SC event identifiers. Rewrote scanner to match
  transactions by `contract[0].parameter.address` and decode function
  calls from the hex-encoded `data[0]` field (`functionName@arg1@arg2`)
- **Parser rewrite** — `parse_receipt()` replaced with `parse_sc_call()`
  that decodes SC function names and arguments directly from transaction
  data instead of receipt topics
- **Channel ID resolution** — `createChannel` events now resolved via
  `getChannelBySlug` SC view query since the channel ID isn't in the
  call data

### Fixed

- Missing semicolon after `public_routes` chain in API router setup
- RocksDB `cf_handle` return type updated to `Arc<BoundColumnFamily>`
  for compatibility with newer `rocksdb` crate versions
- All `WriteBatch` operations now pass `&cf_handle` references correctly
- `KleverTransaction` struct updated to match actual Klever API response
  format (contract array with parameter.address, data array with hex calls)

## [0.4.0] - 2026-03-31

### Added

- **Live Network Stats** — `GET /api/v1/network/stats` now returns real counts
  for `total_messages`, `total_users`, and `total_channels` instead of hardcoded
  zeros, making the website status bar reflect actual network state
- Stat counter keys in `NODE_STATE` column family (`stat_total_messages`,
  `stat_total_users`, `stat_total_channels`) with `get_stat()` and
  `increment_stat()` storage methods
- Automatic counter rebuild on startup — scans existing `MESSAGES`, `USERS`,
  and `CHANNELS` column families when counters are zero (handles upgrade from
  pre-stats versions)
- `NEWS_COMMENTS` column family — indexes comments by parent post
  `(post_id, timestamp, msg_id)` for efficient comment retrieval
- `NewsComment` messages now indexed in `update_indexes()` (previously fell
  through to the catchall and were invisible to queries)
- `encode_news_comment_key()` key encoding function
- `get_comment_count()` method on `Storage` for per-post comment counts

### Fixed

- Website status bar showing `0 Users`, `0 Messages`, `0 Channels` despite
  having stored content — stats endpoint was returning hardcoded zeros
- `NewsComment` messages stored but never indexed, making them unqueryable

## [0.3.0] - 2026-03-30

### Added

- **Node Anchor Verification** — nodes that anchor L2 state on-chain are now
  tracked with verification levels (`active`, `verified`, `none`)
- `ANCHOR_BY_NODE` column family — reverse index of anchors by submitting node
  for efficient per-node anchor history queries
- `compute_anchor_status()` — determines verification level based on anchor
  consistency over the last 7 days
- `get_self_anchor_status()` — reports this node's own anchoring activity
- `GET /api/v1/network/stats` now includes `anchor_status` object with
  `is_anchorer`, `last_anchor_height`, `last_anchor_age_seconds`,
  `total_anchors`, `anchoring_since`
- `GET /api/v1/network/nodes` — new endpoint listing all known peers with
  per-node `anchor_status` (verified, level, last_anchor_age_seconds,
  anchoring_since)
- Chain scanner now writes anchor-by-node reverse index when processing
  `stateAnchored` events

## [0.2.0] - 2026-03-30

### Security
- Authorization guard for all channel admin operations (add/remove mod, kick, ban, pin, invite)
  - Creator-only actions enforced (moderator management)
  - Per-permission checks for moderators (can_kick, can_ban, can_pin, etc.)
  - Cannot kick/ban the channel creator
- Ban enforcement in message pipeline — banned users rejected from channel-scoped messages
- Ban expiration enforcement — temporary bans auto-expire on read and in pipeline
- Per-action-type rate limiting (7 categories per spec Part 5) replacing flat counter
- Rate limiter memory cleanup (evicts expired entries)
- Atomic WriteBatch for follow/unfollow, reaction toggle, repost count updates
- Proper error propagation replacing `unwrap_or_default()` on serialization
- Ban list endpoint moved behind authentication (moderator/creator only)
- Ban reason now required per spec section 2.6
- Monotonic pin sequence to prevent pin_order collisions
- ContentRequest.limit capped to 500 per spec
- Feed endpoint fan-out capped to 200 followed users
- Bookmark removal uses O(1) reverse index instead of O(N) scan

### Added
- **News Engagement**
  - NewsReaction (0x24) and NewsRepost (0x25) message types
  - ReactionPayload reuse for news reactions (like, dislike, love, fire, funny)
  - NewsRepostPayload with optional quote comment (max 512 chars)
  - Storage: news_reactions, reaction_counts, reposts, repost_counts, bookmarks CFs
  - API: GET/POST news reactions, GET/POST reposts, GET/POST/DELETE bookmarks
  - Toggle-based reaction counting with cached counts
  - Repost idempotency (can't repost same post twice, can't repost own post)

- **Channel Administration**
  - 8 new message types: ChannelAddModerator (0x14), ChannelRemoveModerator (0x15),
    ChannelKick (0x16), ChannelBan (0x17), ChannelUnban (0x18), ChannelPinMessage (0x19),
    ChannelUnpinMessage (0x1A), ChannelInvite (0x1B)
  - ModeratorPermissions struct (can_mute, can_kick, can_ban, can_pin, can_edit_info, can_delete_msgs)
  - Storage: channel_moderators, channel_bans, channel_pins, channel_members, channel_invites CFs
  - API: Full CRUD for moderators, bans, pins, invites, member listing
  - Pin message FIFO (max 10 per channel, oldest removed when limit exceeded)
  - Ban records with duration, reason, banned_by tracking

- **Channel Update Extensions**
  - logo_cid, banner_cid, website_url, tags fields on ChannelUpdatePayload
  - Validation for website_url (max 256), tags (max 5, each max 64 chars)

- **Validation**
  - Full validation for all 10 new message types
  - Address format checks (klv1 prefix) on all target_user fields
  - Reason length limits (max 256) for kick/ban payloads

## [0.1.0] - 2026-03-29

### Added
- **Phase 1 — Foundation**
  - Core types: 27+ MessageType enum entries with full payload structs
  - Crypto module: Ed25519 signing in Klever message, TX, and Ogmara protocol formats
  - Keccak-256 hashing, bech32 address encoding, key generation
  - RocksDB storage with 17 column families and key encoding functions
  - Configuration loading from ogmara.toml with safe defaults
  - CLI with run, init, and identity subcommands
  - Node identity management with Lamport clock (atomic CAS)

- **Phase 2 — Networking**
  - libp2p composed behaviour: GossipSub, Kademlia DHT, mDNS, Identify, Request-Response
  - GossipSub topic management (channel, DM, news, profile, network topics)
  - Peer directory with TTL-based staleness tracking
  - Sync protocol: CBOR request-response for on-demand content fetching
  - Message router: 11-step pipeline with Ed25519 signature verification
  - Per-user rate limiting with sliding time windows
  - Type-specific payload validation for all message types

- **Phase 3 — Chain Integration**
  - Klever block scanner with configurable polling interval and cursor persistence
  - SC event parsing for all 8 Ogmara contract events
  - Local state building in RocksDB from on-chain events
  - IPFS client: upload with pinning, bounded retrieval, CID validation, health check
  - MIME type allowlist for uploads

- **Phase 4 — API**
  - REST API with Axum: health, stats, channels, messages, users, news
  - Authenticated endpoints with Klever wallet signature verification
  - WebSocket: authenticated (full read/write) and public (read-only)
  - Admin endpoints with localhost-only enforcement via ConnectInfo
  - 1 MB request body size limit, proper CORS configuration

- **Phase 5 — Advanced**
  - Merkle tree with SHA-256 and domain separation (leaf/internal node prefixes)
  - State manager for computing state roots from users/channels/delegations
  - Notification engine with mention detection and push gateway integration
  - Alerting system: Telegram, Discord, webhook channels with cooldown
  - Embedded admin dashboard (self-contained HTML/CSS/JS, dark/light theme)
  - Dashboard metrics WebSocket with 2-second push interval

- **Social Features (backport)**
  - Follow/Unfollow message types (0x34, 0x35) with validation
  - Three storage column families: follows, followers, follower_counts
  - Bidirectional follow indexes with cached counts
  - API endpoints: followers, following, follow, unfollow, personal feed

### Security
- All ingestion paths (gossip + sync) route through MessageRouter
- Ed25519 signature verification on every message
- CID format validation on all IPFS API calls
- Admin endpoints locked to localhost via IP check middleware
- WebSocket auth verifies Klever signature
- Safe integer parsing (try_from, no silent truncation)
- Mentions capped at 50 per message (anti-amplification)
- Merkle domain separation prevents second-preimage attacks
