#!/bin/sh
# Ogmara L2 Node — Docker entrypoint (v0.46.1+)
#
# Auto-generates a default config at /etc/ogmara/ogmara.toml on first
# run if one doesn't already exist (operator hasn't mounted their own
# via `-v ./ogmara.toml:/etc/ogmara/ogmara.toml:ro`). Then execs the
# node with whatever args the operator passed.
#
# Sourced from `ogmara-node init` so the generated config always
# matches the binary's current `Config::default_toml()` — every
# operator-tunable section is visible (commented or set) so operators
# can discover knobs like `[anchoring.metadata]`, `[network.discovery]`,
# `[api] public_url`, etc., without reading the source.

set -e

CONFIG_PATH="/etc/ogmara/ogmara.toml"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "ogmara-node: no config at $CONFIG_PATH — auto-generating default."
    echo "ogmara-node: mount your own config with"
    echo "             docker run -v \$(pwd)/ogmara.toml:$CONFIG_PATH:ro ..."
    echo "ogmara-node: to override. Defaults are safe for a single-node"
    echo "ogmara-node: starter setup; you'll want to fill in [klever]"
    echo "ogmara-node: node_url / contract_address before doing anything"
    echo "ogmara-node: useful with the chain."
    # Note: the config dir MUST NOT be shared across container replicas —
    # the init writer (main.rs::Commands::Init) is not atomic, so parallel
    # first-starts could clobber each other. One node per data-dir.
    ogmara-node init --output "$CONFIG_PATH"
elif [ ! -r "$CONFIG_PATH" ]; then
    # Common operator footgun: bind-mount a host file owned by `root:root`
    # without making it world-readable. The container runs as user
    # `ogmara` (uid varies per image build) and can't read it; without
    # this branch the node would fail with an opaque "reading
    # /etc/ogmara/ogmara.toml: Permission denied (os error 13)" message.
    echo "ogmara-node: ERROR — $CONFIG_PATH exists but is not readable" >&2
    echo "             by user $(id -un) (uid $(id -u))." >&2
    echo "             If you bind-mounted from the host, ensure the file" >&2
    echo "             is world-readable or owned by the container user." >&2
    echo "             Quick fix on the host: chmod a+r ./ogmara.toml" >&2
    exit 1
fi

exec ogmara-node "$@"
