#!/usr/bin/env bash
# update-node.sh — Pull, build, install, and restart the Ogmara L2 node.
#
# Usage:
#   sudo ./scripts/update-node.sh          # full update (pull + build + install + restart)
#   sudo ./scripts/update-node.sh --local  # skip git pull (build from current working tree)
#
# Assumptions (from TESTPLAN.md):
#   - Source:  /home/webusr/l2-node   (git clone of Ogmara/l2-node)
#   - Binary:  /usr/local/bin/ogmara-node
#   - Config:  /etc/ogmara/ogmara.toml
#   - Service: ogmara-node.service (runs as user ogmara)
#   - Rust toolchain installed for user webusr

set -euo pipefail

# --- Configuration (adjust if your setup differs) ---
REPO_DIR="/home/webusr/l2-node"
REPO_USER="webusr"
BINARY_NAME="ogmara-node"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
SERVICE_NAME="ogmara-node"
BUILD_PROFILE="release"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[update]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
fail() { echo -e "${RED}[error]${NC} $*"; exit 1; }

# --- Pre-flight checks ---
[[ -d "$REPO_DIR" ]] || fail "Source directory not found: $REPO_DIR"
[[ -f "$REPO_DIR/Cargo.toml" ]] || fail "Not a Cargo project: $REPO_DIR"

# Must be root for systemctl and cp to /usr/local/bin
if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root (sudo)"
fi

# --- Step 1: Pull latest changes ---
SKIP_PULL=false
if [[ "${1:-}" == "--local" ]]; then
    SKIP_PULL=true
    log "Skipping git pull (--local mode)"
fi

if [[ "$SKIP_PULL" == false ]]; then
    log "Pulling latest changes..."
    cd "$REPO_DIR"
    # Run git as the repo owner (not root) to avoid permission issues
    sudo -u "$REPO_USER" git fetch --all
    BEFORE=$(sudo -u "$REPO_USER" git rev-parse HEAD)
    sudo -u "$REPO_USER" git pull --ff-only || fail "git pull failed — resolve conflicts manually"
    AFTER=$(sudo -u "$REPO_USER" git rev-parse HEAD)

    if [[ "$BEFORE" == "$AFTER" ]]; then
        warn "Already up to date (${BEFORE:0:8}). Continuing anyway..."
    else
        log "Updated: ${BEFORE:0:8} → ${AFTER:0:8}"
        # Show what changed
        sudo -u "$REPO_USER" git log --oneline "${BEFORE}..${AFTER}"
    fi
fi

# --- Step 2: Build ---
cd "$REPO_DIR"

# Read version from Cargo.toml
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
log "Building ogmara-node v${VERSION} (${BUILD_PROFILE})..."

# Build as repo user (owns the source and cargo cache)
# Source the Rust environment since cargo isn't in root's PATH
sudo -u "$REPO_USER" bash -c 'source "$HOME/.cargo/env" && cargo build --release' 2>&1 | tail -5
BUILD_EXIT=${PIPESTATUS[0]}

if [[ $BUILD_EXIT -ne 0 ]]; then
    fail "Build failed with exit code $BUILD_EXIT"
fi

BINARY="$REPO_DIR/target/${BUILD_PROFILE}/${BINARY_NAME}"
[[ -f "$BINARY" ]] || fail "Binary not found at $BINARY"

log "Build successful: $(ls -lh "$BINARY" | awk '{print $5}')"

# --- Step 3: Install ---
# Save old binary for rollback
if [[ -f "$INSTALL_PATH" ]]; then
    OLD_VERSION=$("$INSTALL_PATH" --version 2>/dev/null || echo "unknown")
    cp "$INSTALL_PATH" "${INSTALL_PATH}.bak"
    log "Backed up previous binary (${OLD_VERSION}) → ${INSTALL_PATH}.bak"
fi

cp "$BINARY" "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

INSTALLED_VERSION=$("$INSTALL_PATH" --version 2>/dev/null || echo "v${VERSION}")
log "Installed: ${INSTALLED_VERSION}"

# --- Step 4: Restart ---
log "Restarting ${SERVICE_NAME}..."
systemctl restart "$SERVICE_NAME"

# Wait briefly for startup
sleep 2

if systemctl is-active --quiet "$SERVICE_NAME"; then
    log "Service is running"
else
    warn "Service may have failed to start — checking logs..."
    journalctl -u "$SERVICE_NAME" --no-pager -n 20
    echo ""
    warn "Rollback available: sudo cp ${INSTALL_PATH}.bak ${INSTALL_PATH} && sudo systemctl restart ${SERVICE_NAME}"
    exit 1
fi

# --- Step 5: Verify ---
# Show recent logs to confirm clean startup
echo ""
log "Recent logs:"
journalctl -u "$SERVICE_NAME" --no-pager -n 10 --since "10 seconds ago"

# Quick health check via API
echo ""
if command -v curl &>/dev/null; then
    log "Health check:"
    HEALTH=$(curl -sf http://127.0.0.1:41721/api/v1/health 2>/dev/null || echo "")
    if [[ -n "$HEALTH" ]]; then
        echo "  $HEALTH"
    else
        warn "Health endpoint not responding yet (may still be starting)"
    fi
fi

echo ""
log "Update complete: ogmara-node v${VERSION}"
