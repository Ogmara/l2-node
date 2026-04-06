# Building the Ogmara L2 Node

## Prerequisites

### System packages (Debian/Ubuntu)

```bash
sudo apt install -y \
  build-essential pkg-config libssl-dev \
  libclang-dev cmake protobuf-compiler \
  git curl jq
```

### Rust toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

Minimum Rust version: **1.94+**

## Build

```bash
git clone https://github.com/Ogmara/l2-node.git
cd l2-node
cargo build --release
```

Build takes ~2 minutes on 4 cores. The binary is at
`target/release/ogmara-node`.

### Install

```bash
sudo cp target/release/ogmara-node /usr/local/bin/ogmara-node
sudo chmod +x /usr/local/bin/ogmara-node
ogmara-node --version
```

## Configuration

Copy the example config and edit:

```bash
sudo mkdir -p /etc/ogmara
sudo cp ogmara.example.toml /etc/ogmara/ogmara.toml
```

Required settings:
- `klever.node_url` — Klever RPC endpoint
- `klever.api_url` — Klever API endpoint
- `klever.contract_address` — Ogmara KApp smart contract address

Important settings:
- `klever.scan_interval_ms` — Set to `60000` (60s) for testnet to avoid rate limits
- `api.listen_addr` — Use `127.0.0.1` behind a reverse proxy, `0.0.0.0` for direct access
- `logging.level` — Use `info` for production, `debug` for troubleshooting

See `ogmara.example.toml` for all options.

## Deployment

### Systemd service

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ogmara
sudo mkdir -p /var/lib/ogmara/node
sudo chown -R ogmara:ogmara /var/lib/ogmara/node
```

```ini
# /etc/systemd/system/ogmara-node.service
[Unit]
Description=Ogmara L2 Node
After=network-online.target ogmara-ipfs.service
Wants=network-online.target

[Service]
Type=simple
User=ogmara
Group=ogmara
ExecStart=/usr/local/bin/ogmara-node --config /etc/ogmara/ogmara.toml
WorkingDirectory=/var/lib/ogmara/node
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ogmara/node
PrivateTmp=true
LimitNOFILE=65535
MemoryMax=4G

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable ogmara-node
sudo systemctl start ogmara-node
```

### Reverse proxy (Apache)

The node API should be behind a reverse proxy with SSL. See
`docs/deployment/reverse-proxy.md` for Apache and Nginx configs.

Key routes:
- `/api/` → `http://127.0.0.1:41721/api/`
- `/api/v1/ws` → `ws://127.0.0.1:41721/api/v1/ws` (WebSocket upgrade)
- `/admin/` → deny all (block external access)

### Firewall

```bash
sudo ufw allow 41720/udp  # libp2p QUIC
sudo ufw allow 41720/tcp  # libp2p TCP fallback
# Port 41721 (API) stays behind reverse proxy — don't expose directly
```

## State Anchoring (optional)

State anchoring publishes a Merkle root of L2 state to the Klever SC.
Most nodes do NOT anchor — it's optional and costs ~5 KLV per TX.

### Setup

1. **Anchor wallet**: The node uses a separate wallet for anchor TXs.
   By default it uses the node's auto-generated identity key. You can
   set a specific key via config or env var:

   ```toml
   [anchoring]
   enabled = true
   interval_seconds = 3600    # anchor every hour
   wallet_key = ""            # hex private key, or use env var
   ```

   Or via environment: `OGMARA_ANCHOR_WALLET_KEY=<hex>`

2. **Fund the anchor wallet**: The wallet needs KLV to pay for SC TXs.
   Check the node logs on startup for the anchor wallet address:
   ```
   "State anchoring using node identity key"
   ```
   The address is derived from the identity key. Send KLV to it.
   Cost: ~120 KLV/day at hourly intervals.

3. **Authorize on the SC**: The SC owner must add the anchor wallet to
   the authorized anchorer list:
   ```bash
   koperator sc invoke <CONTRACT> authorizeAnchorer \
       --args "Address:<ANCHOR_WALLET_ADDRESS>" \
       -k owner-wallet.pem -n <NODE_URL> --await -s
   ```

4. **Trigger manually** (for testing):
   ```bash
   curl -X POST http://127.0.0.1:41721/admin/state/anchor
   ```

### Important

- The anchor wallet is **different** from the SC owner wallet
- The anchor wallet needs its own KLV balance for TX fees
- It must be authorized on the SC before it can anchor
- If the wallet runs out of KLV, anchoring silently fails

## Update

```bash
cd ~/l2-node
git pull
cargo build --release
sudo systemctl stop ogmara-node
sudo cp target/release/ogmara-node /usr/local/bin/ogmara-node
sudo systemctl start ogmara-node
```

Or use the provided script: `sudo ./scripts/update-node.sh`

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 41720 | UDP/TCP | libp2p peer communication |
| 41721 | TCP | REST/WebSocket API (localhost only) |

## RocksDB compatibility note

The `rocksdb` crate version may differ between systems. If you see
`Arc<BoundColumnFamily>` type errors during build, ensure `cf_handle`
calls pass references (`&cf_handle`) to batch operations.
