# Changelog

All notable changes to the Ogmara L2 node will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
