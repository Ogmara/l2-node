# Ogmara L2 Node — Multi-stage Docker build
#
# Build:  docker build -t ogmara/ogmara:l2-node-0.16.0 .
# Run:    docker run -v ogmara-data:/data -v ./ogmara.toml:/etc/ogmara/ogmara.toml:ro \
#           -p 41720:41720/udp -p 41720:41720/tcp -p 41721:41721 \
#           ogmara/ogmara:l2-node-0.16.0

# --- Stage 1: Build ---
FROM rust:1.94-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev libclang-dev cmake protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

# Build release binary
RUN cargo build --release && strip target/release/ogmara-node

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin ogmara \
    && mkdir -p /data /etc/ogmara \
    && chown ogmara:ogmara /data

COPY --from=builder /build/target/release/ogmara-node /usr/local/bin/ogmara-node
COPY ogmara.example.toml /etc/ogmara/ogmara.example.toml

USER ogmara
WORKDIR /data

# libp2p (QUIC + TCP)
EXPOSE 41720/udp
EXPOSE 41720/tcp
# REST/WebSocket API
EXPOSE 41721/tcp

ENTRYPOINT ["ogmara-node"]
CMD ["--config", "/etc/ogmara/ogmara.toml"]
