# Ogmara L2 Node

The core network node for the [Ogmara](https://ogmara.org) decentralized chat and news platform on [Klever](https://klever.org) blockchain.

Anyone can run an L2 node. Nodes form a permissionless peer-to-peer network that stores messages, relays data, and serves client connections.

## Run a Node

### Docker (recommended)

The fastest way to run a node. Requires [Docker](https://docs.docker.com/engine/install/) and [IPFS (Kubo)](https://docs.ipfs.tech/install/command-line/#install-official-binary-distributions).

```bash
# Pull the latest image
docker pull ogmara/ogmara:l2-node-latest

# Create config directory
mkdir -p ~/ogmara-node
curl -sO https://raw.githubusercontent.com/Ogmara/l2-node/main/ogmara.example.toml
mv ogmara.example.toml ~/ogmara-node/ogmara.toml
# Edit ~/ogmara-node/ogmara.toml if needed (testnet defaults are pre-filled)

# Start the node
docker run -d \
  --name ogmara-node \
  --restart unless-stopped \
  -v ~/ogmara-node/ogmara.toml:/etc/ogmara/ogmara.toml:ro \
  -v ogmara-data:/data \
  -p 41720:41720/udp \
  -p 41720:41720/tcp \
  -p 41721:41721 \
  ogmara/ogmara:l2-node-latest

# Verify
curl -s http://localhost:41721/api/v1/health | jq .
```

### Docker Compose (node + IPFS)

For a complete setup with IPFS media storage, use docker-compose:

```bash
curl -sO https://raw.githubusercontent.com/Ogmara/l2-node/main/docker-compose.yml
curl -sO https://raw.githubusercontent.com/Ogmara/l2-node/main/ogmara.example.toml
mv ogmara.example.toml ogmara.toml

docker compose up -d
```

See [docker-compose.yml](docker-compose.yml) for the full setup.

### Build from source

Requires Rust 1.94+ and system packages. See [BUILDING.md](BUILDING.md) for full instructions.

```bash
sudo apt install -y build-essential pkg-config libssl-dev libclang-dev cmake protobuf-compiler
cargo build --release
sudo cp target/release/ogmara-node /usr/local/bin/
```

## Requirements

### IPFS (recommended)

The L2 node connects to a local [IPFS (Kubo)](https://docs.ipfs.tech/install/) node for media storage. Without IPFS, the node still handles text messages and chat but cannot store or serve media (images, videos, files).

```bash
# Install Kubo
wget https://dist.ipfs.tech/kubo/v0.40.1/kubo_v0.40.1_linux-amd64.tar.gz
tar xzf kubo_v0.40.1_linux-amd64.tar.gz
sudo mv kubo/ipfs /usr/local/bin/
ipfs init && ipfs daemon &
```

The node config expects IPFS at `http://127.0.0.1:5001` (default Kubo API port).

### Firewall

```bash
sudo ufw allow 41720/udp  # libp2p QUIC (primary)
sudo ufw allow 41720/tcp  # libp2p TCP (fallback)
# Port 41721 (API) — only expose if not behind reverse proxy
```

## Configuration

See [ogmara.example.toml](ogmara.example.toml) for all options. The example config comes with **testnet defaults** pre-filled — just start the node and it works.

For mainnet, uncomment the mainnet section in the config file.

| Setting | Default | Description |
|---------|---------|-------------|
| `klever.contract_address` | testnet SC | Ogmara KApp smart contract |
| `klever.scan_interval_ms` | 60000 | Chain scan interval (60s, rate-limit safe) |
| `network.listen_port` | 41720 | libp2p port |
| `api.listen_port` | 41721 | REST/WS API port |
| `api.listen_addr` | 127.0.0.1 | Bind address (use 0.0.0.0 for direct access) |
| `ipfs.api_url` | http://127.0.0.1:5001 | Local IPFS Kubo API |

## Connecting to the Network

Add bootstrap peers to connect to existing nodes:

```toml
[network]
bootstrap_nodes = ["/ip4/<PEER_IP>/tcp/41720/p2p/<PEER_ID>"]
```

Find your node's peer ID: `docker logs ogmara-node 2>&1 | grep local_peer_id`

Peer IDs are stable across restarts.

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

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 41720 | UDP/TCP | libp2p (QUIC + TCP) peer communication |
| 41721 | TCP | REST / WebSocket API |

## Docker Hub

All images at [`ogmara/ogmara`](https://hub.docker.com/r/ogmara/ogmara):
- `ogmara/ogmara:l2-node-latest` — latest stable
- `ogmara/ogmara:l2-node-X.Y.Z` — specific version

## Further Reading

- [BUILDING.md](BUILDING.md) — Build from source, systemd, Docker, anchoring setup
- [Node Operator Guide](https://github.com/Ogmara/ogmara/blob/main/docs/guides/node-operator-guide.md) — What a node does, how data is stored, costs
- [ogmara.example.toml](ogmara.example.toml) — Full configuration reference

## License

MIT
