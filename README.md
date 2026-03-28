# Ogmara L2 Node

The core network node for the [Ogmara](https://ogmara.org) decentralized chat and news platform on [Klever](https://klever.org) blockchain.

Anyone can run an L2 node. Nodes form a permissionless peer-to-peer network that stores messages, relays data, and serves client connections.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                       L2 Node                           │
│                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │   libp2p    │  │  Chain       │  │  IPFS         │  │
│  │   Network   │  │  Scanner     │  │  Client       │  │
│  └──────┬──────┘  └──────┬───────┘  └───────┬───────┘  │
│         │                │                   │          │
│  ┌──────▼────────────────▼───────────────────▼───────┐  │
│  │                 Message Router                     │  │
│  └──────┬────────────────┬───────────────────┬───────┘  │
│         │                │                   │          │
│  ┌──────▼──────┐  ┌──────▼───────┐  ┌───────▼───────┐  │
│  │  Storage    │  │  State       │  │  Notification │  │
│  │  (RocksDB)  │  │  (Merkle)   │  │  Engine       │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │                REST / WebSocket API               │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Generate default config
ogmara-node init

# Edit ogmara.toml with your Klever node/API URLs

# Start the node
ogmara-node run

# Show node identity
ogmara-node identity
```

## Building

```bash
cargo build --release
```

Binary: `target/release/ogmara-node`

## Configuration

See [ogmara.example.toml](ogmara.example.toml) for all options.

Key settings:
- `klever.node_url` / `klever.api_url` -- Klever RPC endpoints (testnet or mainnet)
- `klever.contract_address` -- Ogmara KApp smart contract address
- `network.listen_port` -- libp2p port (default: 41720)
- `api.listen_port` -- REST/WS API port (default: 41721)

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 41720 | UDP/TCP | libp2p (QUIC + TCP) |
| 41721 | TCP | REST / WebSocket API |

## Project Structure

```
src/
  main.rs           -- CLI entry point
  config.rs         -- ogmara.toml loading
  node.rs           -- node lifecycle orchestration
  crypto/           -- Ed25519, Keccak-256, signing formats
  messages/         -- envelope, 25+ message types, payloads
  storage/          -- RocksDB with 14 column families
  network/          -- libp2p, GossipSub, sync (Phase 2)
  chain/            -- Klever chain scanner (Phase 3)
  ipfs/             -- IPFS client (Phase 3)
  api/              -- REST/WS API (Phase 4)
  notifications/    -- mention detection, push (Phase 5)
```

## Implementation Phases

- **Phase 1** (current): Foundation -- types, crypto, config, storage, CLI
- **Phase 2**: Networking -- libp2p, GossipSub, message routing, sync
- **Phase 3**: Chain integration -- Klever scanner, IPFS client
- **Phase 4**: API -- REST endpoints, WebSocket, auth middleware
- **Phase 5**: Advanced -- Merkle tree, notifications, admin dashboard, alerts

## Tech Stack

- **Language**: Rust
- **Async**: Tokio
- **Storage**: RocksDB
- **Networking**: libp2p (QUIC + TCP)
- **Serialization**: MessagePack (rmp-serde)
- **Crypto**: ed25519-dalek, sha3 (Keccak-256), x25519-dalek, aes-gcm
- **HTTP**: Axum (Phase 4)
- **Logging**: tracing (structured JSON)

## License

MIT
