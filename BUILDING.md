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
