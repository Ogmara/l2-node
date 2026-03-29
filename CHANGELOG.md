# Changelog

All notable changes to the Ogmara L2 node will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
