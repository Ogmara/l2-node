//! Configuration loading and validation for the Ogmara L2 node.
//!
//! Loads from `ogmara.toml` (spec section 5). All Klever URLs are user-configured,
//! never hardcoded. Secrets (API tokens, webhook URLs) come from environment variables.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// Top-level node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub klever: KleverConfig,
    #[serde(default)]
    pub ipfs: IpfsConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub push_gateway: PushGatewayConfig,
    #[serde(default)]
    pub anchoring: AnchoringConfig,
    #[serde(default)]
    pub snapshot: SnapshotConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Cross-node media fallback policy (spec 3 §media-fetch, l2-node
    /// 0.46.7+). Separate from `[ipfs]` because the concerns are
    /// distinct: `[ipfs]` is local-Kubo connection + handler resource
    /// caps; `[media]` is the SC-registered-peer fallback used when a
    /// CID misses locally.
    #[serde(default)]
    pub media: MediaConfig,
    /// Channel-history backfill / reconciliation policy (spec 1
    /// §channel-history-reconciliation, l2-node 0.47.0+).
    #[serde(default)]
    pub backfill: BackfillConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Path to store node identity key and data.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// libp2p listen port (default: 41720).
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Bootstrap node multiaddresses for peer discovery.
    #[serde(default = "default_bootstrap_nodes")]
    pub bootstrap_nodes: Vec<String>,
    /// Maximum peer connections.
    #[serde(default = "default_max_peers")]
    pub max_peers: u32,
    /// Enable mDNS for local peer discovery.
    #[serde(default = "default_true")]
    pub enable_mdns: bool,
    /// Network identifier for peer isolation ("mainnet" or "testnet").
    /// Nodes on different networks will refuse to peer with each other.
    /// If not set, auto-detected from klever.node_url at startup.
    #[serde(default)]
    pub network_id: Option<String>,
    /// On-chain peer-discovery tuning (spec 13 §7). Added in v0.45.0.
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    /// SC-driven bootstrap control surface (spec 13 §4.2, l2-node
    /// 0.46.5+). Tier 3 is the primary boot path when
    /// `bootstrap_nodes = []`; isolated-subnet mode is `enabled =
    /// false` + non-empty `bootstrap_nodes`.
    #[serde(default)]
    pub sc_discovery: ScDiscoveryConfig,
    /// Onion transport — external Tor daemon + SOCKS5 wrapper (spec
    /// 13 §6.4, l2-node 0.46.9+). Operator-facing knobs for hosting
    /// a hidden service and (in a future release) dialling onion peers
    /// through a local Tor SOCKS proxy. Disabled by default —
    /// operators with regulatory-resilience requirements opt in.
    #[serde(default)]
    pub tor: TorConfig,
    /// Presence-gossip subsystem (spec 13 §10, l2-node 0.48.0+). Off-
    /// chain, opt-in discovery channel for service-provider operators
    /// who want to be discoverable without committing to on-chain
    /// anchoring economics. Default-off — participation is explicit,
    /// mirroring `[anchoring]`. Independent of `[anchoring]` and
    /// `[anchoring.metadata]`.
    #[serde(default)]
    pub presence: PresenceConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: default_listen_port(),
            bootstrap_nodes: default_bootstrap_nodes(),
            max_peers: default_max_peers(),
            enable_mdns: true,
            network_id: None,
            discovery: DiscoveryConfig::default(),
            sc_discovery: ScDiscoveryConfig::default(),
            tor: TorConfig::default(),
            presence: PresenceConfig::default(),
        }
    }
}

/// On-chain peer-discovery tuning. All fields are optional with
/// spec-aligned defaults; operators only need to override for local
/// deployments or unusually-tight networks.
///
/// Reference: [docs/specs/13-node-discovery.md §7](../../docs/specs/13-node-discovery.md#7-client-side-filtering-rules).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Drop dial-candidate peers whose on-chain `lastAnchorAt` is
    /// older than this many days. Default 7 (spec 13 §7). Local
    /// dev/test deployments may want a longer threshold; production-
    /// facing nodes should stick with the default.
    #[serde(default = "default_max_peer_staleness_days")]
    pub max_peer_staleness_days: u32,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            max_peer_staleness_days: default_max_peer_staleness_days(),
        }
    }
}

fn default_max_peer_staleness_days() -> u32 {
    7
}

/// SC-driven bootstrap control surface (spec 13 §4.2, l2-node 0.46.5+).
///
/// Reference: [docs/specs/13-node-discovery.md §4.2](../../docs/specs/13-node-discovery.md#42-tier-2--bootstrap_nodes-config-override-no-defaults-l2-node-0465).
///
/// Three operating modes by combination with `[network] bootstrap_nodes`:
///
/// | `bootstrap_nodes` | `enabled` | Mode |
/// |---|---|---|
/// | `[]` (default) | `true` (default) | Pure SC — tier 3 is the only boot path; cold-start retries every `retry_interval_secs` if Klever RPC is unreachable. |
/// | non-empty | `true` | Hybrid — dial explicit peers; SC supplements the book in parallel. |
/// | non-empty | `false` | Isolated subnet — dial explicit peers only; Klever API never queried for discovery. |
/// | `[]` | `false` | **Rejected at config-load** — no way to discover peers. |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScDiscoveryConfig {
    /// Whether the SC-discovery background task runs at all. Default
    /// `true`. Set `false` for an isolated subnet that never queries
    /// Klever for peer discovery — useful for operators in regions
    /// where Klever endpoints are geo-blocked or surveilled. Note: on-
    /// chain identity resolution (`klv1...` → wallet) is unavailable
    /// in this mode; users on the subnet operate as ephemeral
    /// `ogd1...` identities until they can reach the chain layer.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Cold-start retry cadence in seconds — how often the discovery
    /// task retries `getActiveNodes` when `bootstrap_nodes = []` AND
    /// the peer book is empty AND the previous fan-out persisted zero
    /// new peers. Default 60 seconds. Only applies during cold-start;
    /// once at least one peer is persisted, the task transitions to
    /// the steady-state 1-hour periodic cadence.
    #[serde(default = "default_sc_retry_interval_secs")]
    pub retry_interval_secs: u64,
    /// Maximum number of SC-discovered peers to dial per cold-start
    /// fan-out. Default 5. The fan-out still PERSISTS up to 256 peers
    /// (matches `PEER_DIRECTORY` cap); this knob caps the immediate
    /// dial set so a fresh node doesn't burst-connect to dozens of
    /// peers it doesn't have routes for yet.
    #[serde(default = "default_sc_max_candidates")]
    pub max_candidates: u32,
}

impl Default for ScDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retry_interval_secs: default_sc_retry_interval_secs(),
            max_candidates: default_sc_max_candidates(),
        }
    }
}

fn default_sc_retry_interval_secs() -> u64 {
    60
}

fn default_sc_max_candidates() -> u32 {
    5
}

/// Onion-transport configuration (spec 13 §6.4, l2-node 0.46.9+).
///
/// We integrate with an **external** Tor daemon (the operator manages
/// the daemon lifecycle) via a SOCKS5 dialer + an inbound TCP listen
/// for the hidden-service forward. No embedded Tor (arti) dependency
/// in v0.46.9 — keeps the build minimal and the audit surface
/// focused on the small hand-rolled SOCKS5 module
/// ([`crate::network::tor`]).
///
/// **v0.46.9 scope (this release):**
/// - Config surface fully wired.
/// - SOCKS5 dialer module shipped with security-critical properties
///   (DNS-leak prevention, no IP-fallthrough, RFC 1928 compliance).
/// - **Inbound onion support**: when `listen_onion_hostname` is set
///   AND `listen_onion_port` is non-zero, the swarm listens on
///   `/ip4/127.0.0.1/tcp/listen_onion_port` so the operator's Tor
///   hidden-service can forward traffic to it.
/// - Outbound onion multiaddrs are still refused by the libp2p
///   dialer — the SOCKS5-backed libp2p `Transport` integration is
///   deferred to a future release (onion Phase 2; not a mainnet
///   blocker). Peers that publish onion-only addresses are not
///   yet dialable, but ARE discoverable (their multiaddrs appear in
///   `bootstrap-candidates` with `transport: "onion"`).
///
/// **Operator workflow:** see spec 13 §6.4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    /// Master switch. Default `false` — onion support is opt-in.
    /// Enabling this:
    /// 1. Validates `socks_proxy` parses cleanly.
    /// 2. (future release) Registers the SOCKS5-backed libp2p Transport
    ///    for outbound `/onion3/...` dials.
    /// 3. Configures inbound listen on the loopback TCP port that
    ///    the operator's external Tor service forwards the hidden
    ///    service to.
    #[serde(default)]
    pub enabled: bool,
    /// Address of the local Tor SOCKS5 proxy. Default
    /// `127.0.0.1:9050` (the Tor daemon default). Operators with
    /// non-standard Tor setups override.
    ///
    /// The dialer enforces a localhost-only check at config-load:
    /// non-loopback SOCKS proxies are refused because they would
    /// route every onion dial through a remote SOCKS server,
    /// breaking the deanonymisation model. Operators with genuine
    /// remote-SOCKS needs document an override path in a future
    /// release.
    #[serde(default = "default_tor_socks_proxy")]
    pub socks_proxy: String,
    /// Loopback TCP port the swarm listens on when
    /// `listen_onion_hostname` is set. The operator's Tor service
    /// forwards `<listen_onion_hostname>:<onion_virtual_port>` to
    /// this port (typically `127.0.0.1:<listen_onion_port>` in the
    /// `HiddenServicePort` torrc directive). Zero disables the
    /// inbound listen even when other tor fields are set.
    #[serde(default)]
    pub listen_onion_port: u16,
    /// `.onion` hostname of this node's hidden service, copied from
    /// `/var/lib/tor/<hs_dir>/hostname` after the Tor daemon
    /// generates it. Empty disables both the inbound listen and any
    /// `setNodeMetadata` advertisement. The string is validated at
    /// config-load: must end in `.onion`, must be ASCII, must parse
    /// as a v3 onion address (56-char base32 plus the suffix) when
    /// non-empty.
    #[serde(default)]
    pub listen_onion_hostname: String,
    /// When `true`, the metadata reconciler appends the onion
    /// multiaddr (`/onion3/<hostname-without-suffix>:<port>`) to the
    /// desired list it compares against the on-chain
    /// `getNodeMetadata(self)`. The operator still has to click
    /// Publish in the dashboard to actually broadcast — no proxy
    /// signing (spec 12 §6.2). Default `false` so operators opt
    /// into the advertisement separately from running the hidden
    /// service.
    #[serde(default)]
    pub advertise_onion_in_metadata: bool,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socks_proxy: default_tor_socks_proxy(),
            listen_onion_port: 0,
            listen_onion_hostname: String::new(),
            advertise_onion_in_metadata: false,
        }
    }
}

fn default_tor_socks_proxy() -> String {
    "127.0.0.1:9050".to_string()
}

/// Presence-gossip subsystem configuration (spec 13 §10, l2-node 0.48.0+).
///
/// Off-chain, opt-in discovery channel. When `enabled = true` AND
/// `[api] public_url` is non-empty, the node periodically broadcasts a
/// signed `PresenceRecord` on the
/// `/ogmara/{network_id}/presence/v1` gossipsub topic so other nodes
/// and the public Network page can list this node without on-chain
/// registration.
///
/// Independent of `[anchoring]` and `[anchoring.metadata]`:
///   - presence-only: lightweight, no KLV, no anchoring duties
///   - anchoring + metadata: full participant, on-chain trust anchor
///   - both: belt-and-suspenders, recommended for production anchoring
///     operators because it provides discovery resilience even if
///     Klever RPC is briefly unreachable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceConfig {
    /// Master switch. Default `false` — participation is explicit,
    /// mirroring `[anchoring]`. Independent of `[anchoring]`.
    #[serde(default)]
    pub enabled: bool,
    /// How long our records stay valid in peers' caches (and the cap
    /// on how stale our cached records of OTHER nodes can be before we
    /// drop them). 24h default; max 7 days = 604_800 (spec 13 §10.3).
    /// Validated at config-load when `enabled = true`.
    #[serde(default = "default_presence_record_ttl_secs")]
    pub record_ttl_secs: u64,
    /// How often we re-sign and re-broadcast our own record. Must be
    /// strictly less than `record_ttl_secs / 2` so peers always have a
    /// valid record between re-broadcasts (spec 13 §10.5). Validated
    /// at config-load when `enabled = true`. Default 6h = 21_600.
    #[serde(default = "default_presence_rebroadcast_interval_secs")]
    pub rebroadcast_interval_secs: u64,
    /// Peers whose presence records we never accept (libp2p PeerIds,
    /// base58-encoded `12D3KooW...` strings). Useful for surgical
    /// exclusion of known-bad operators without touching the SC
    /// denylist. Empty default. Validated at config-load — entries
    /// that fail to parse as a `PeerId` abort startup with a
    /// config-fix message.
    #[serde(default)]
    pub denylist: Vec<String>,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            record_ttl_secs: default_presence_record_ttl_secs(),
            rebroadcast_interval_secs: default_presence_rebroadcast_interval_secs(),
            denylist: Vec::new(),
        }
    }
}

fn default_presence_record_ttl_secs() -> u64 {
    86_400
}
fn default_presence_rebroadcast_interval_secs() -> u64 {
    // 1 hour. Earlier drafts of spec 13 §10.5 chose 6h (= 21_600s)
    // to minimize gossip traffic, but real-operator testing on small
    // testnets (2-3 active nodes) showed that combined with the
    // <= 3 peers initial-broadcast threshold (lowered to >= 1 in
    // v0.48.2, see network/mod.rs maybe_publish_initial_presence), a
    // 6h cadence meant freshly-restarted nodes saw an empty presence
    // cache for hours. 1h is the smallest interval that still keeps
    // gossip traffic bounded but lets caches converge within a
    // realistic operator-debug window.
    3_600
}

/// Upper bound on `record_ttl_secs` (7 days, per spec 13 §10.3).
pub const PRESENCE_MAX_RECORD_TTL_SECS: u64 = 7 * 24 * 3600;

/// Cross-node media-fetch fallback policy (spec 3 §media-fetch,
/// l2-node 0.46.7+).
///
/// When a `/api/v1/media/:cid` request misses the local Kubo, the
/// node optionally fans out to SC-registered peers to retrieve the
/// content. Trust set is strict at launch (spec 3, D2 of the
/// mainnet-blockers plan): only nodes returned by the SC's
/// `getActiveNodes` AND with `lastAnchorAt` within the
/// `[network.discovery] max_peer_staleness_days` window AND with a
/// usable `api_endpoint` known to the local peer directory. No
/// unregistered-peer fallback at launch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaConfig {
    /// Master switch. Default `true` — enables the fallback for fresh
    /// installs. Operators who want strictly-local serving (e.g.
    /// privacy-conscious archive nodes that should not generate
    /// outbound HTTP requests to peers) set this to `false`.
    #[serde(default = "default_true")]
    pub peer_fallback_enabled: bool,
    /// Max number of peer candidates to dial in parallel per fallback
    /// fetch. Each candidate is dialed concurrently; the first 200
    /// response wins, the others are cancelled. Default 3 (spec 3,
    /// D2 of the mainnet-blockers plan).
    #[serde(default = "default_media_peer_fallback_fanout")]
    pub peer_fallback_fanout: usize,
    /// Connect timeout per peer fallback dial, in seconds. Default 5.
    /// Short enough that a dead peer doesn't stall the request; long
    /// enough that a healthy peer behind moderate latency still
    /// responds in time.
    #[serde(default = "default_media_peer_fallback_connect_secs")]
    pub peer_fallback_connect_timeout_secs: u64,
    /// End-to-end read budget per peer fallback dial, in seconds.
    /// Default 30 — accommodates a large image transfer over a slow
    /// link. The overall fallback fetch is bounded by this timeout
    /// for the racing future as well.
    #[serde(default = "default_media_peer_fallback_read_secs")]
    pub peer_fallback_read_timeout_secs: u64,
    /// Global cap on concurrent fan-out operations across all
    /// clients. Bounds the node's outbound network footprint when
    /// many clients trigger fallbacks simultaneously. Default 16
    /// (spec 3, mainnet-blockers plan §3 step 3).
    #[serde(default = "default_media_peer_fallback_global_concurrent")]
    pub peer_fallback_global_concurrent: usize,
    /// How long the SC-active-nodes candidate snapshot is cached
    /// before the next fallback request triggers a refresh. Bounds
    /// SC view-call load — at the default 300s, a node serving
    /// continuous fallback fetches makes at most ~12 calls/hour
    /// against `getActiveNodes`. Spec 3, mainnet-blockers plan §3
    /// step 3.
    #[serde(default = "default_media_peer_fallback_candidate_cache_secs")]
    pub peer_fallback_candidate_cache_secs: u64,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            peer_fallback_enabled: true,
            peer_fallback_fanout: default_media_peer_fallback_fanout(),
            peer_fallback_connect_timeout_secs:
                default_media_peer_fallback_connect_secs(),
            peer_fallback_read_timeout_secs:
                default_media_peer_fallback_read_secs(),
            peer_fallback_global_concurrent:
                default_media_peer_fallback_global_concurrent(),
            peer_fallback_candidate_cache_secs:
                default_media_peer_fallback_candidate_cache_secs(),
        }
    }
}

fn default_media_peer_fallback_fanout() -> usize {
    3
}

fn default_media_peer_fallback_connect_secs() -> u64 {
    5
}

fn default_media_peer_fallback_read_secs() -> u64 {
    30
}

fn default_media_peer_fallback_global_concurrent() -> usize {
    16
}

fn default_media_peer_fallback_candidate_cache_secs() -> u64 {
    300
}

/// Channel-history backfill / reconciliation (spec 1 §channel-history-
/// reconciliation, l2-node 0.47.0+).
///
/// Triggered on the **first** `subscribe_channel(channel_id)` for a
/// channel whose local `CHANNEL_MSGS` index is empty (cold-join). The
/// node requests the missing history from up to `fanout` peers
/// concurrently, races for the first non-empty response, then keeps
/// requesting from the same peer in cursor batches until the peer
/// signals `has_more = false`.
///
/// **Per-node semantics**: once reconciled, the local CHANNEL_MSGS is
/// the system of record. Re-subscribing the same channel does NOT
/// re-trigger — `prefix_iter_cf` will return non-zero rows. Operators
/// who want to re-reconcile a stale local history set
/// `force_resync_if_stale_days > 0`.
///
/// **Wire protocol**: forward-compatible with a future negentropy-
/// style multi-round fingerprint exchange. v0.47.0 always sends an
/// empty `fingerprint` payload, which responders interpret as
/// "the requester has no data — bulk-send everything in the
/// configured window". The `fingerprint` field will be populated in
/// a future v0.47.x when the steady-state-overlap case becomes
/// worth the bandwidth-savings work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackfillConfig {
    /// Master switch. Default `true` — fresh nodes auto-reconcile on
    /// cold-join. Operators on bandwidth-constrained connections set
    /// `false` to force users to rely on real-time gossip only.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How far back the request asks for envelopes, in days. Default
    /// 30. Archive operators set `max_age_days = unlimited` (which we
    /// represent as `u64::MAX`); responder-side this maps to "no
    /// time-window filter, just respect max_envelopes_per_response".
    #[serde(default = "default_backfill_max_age_days")]
    pub max_age_days: u64,
    /// Cap on concurrent peer-side reconciliation requests per cold-
    /// join. Default 3. Lower to 1 on bandwidth-tight connections.
    #[serde(default = "default_backfill_fanout")]
    pub fanout: usize,
    /// Server-side: max concurrent reconciliation requests this node
    /// will serve to ONE peer simultaneously. Default 4. Excess
    /// requests respond with `server_capped = true` + empty envelopes
    /// so the requester knows to back off.
    #[serde(default = "default_backfill_server_max_concurrent_per_peer")]
    pub server_max_concurrent_per_peer: usize,
    /// Server-side: max concurrent reconciliation requests this node
    /// will serve to ONE (peer, channel) tuple simultaneously. Default
    /// 1. Stops a single peer hammering a single channel with
    /// pipelined requests.
    #[serde(default = "default_backfill_server_max_concurrent_per_channel")]
    pub server_max_concurrent_per_channel: usize,
    /// Re-reconciliation knob. Default `0` = off. When `> 0`, re-
    /// triggers reconciliation on subscribe_channel if the local
    /// history's newest envelope is older than this many days. The
    /// gossip mesh fills gaps in real time so the default-off is
    /// usually right; archive nodes set 1 for "always catch up".
    #[serde(default)]
    pub force_resync_if_stale_days: u64,
    /// Server-side: max envelopes per response. Default 1000. Larger
    /// fits more in a single libp2p response (cap is ~10 MiB CBOR);
    /// smaller cuts the worst-case latency. Total transfer is the
    /// same — clients page via the `next_cursor` field until
    /// `has_more = false`.
    #[serde(default = "default_backfill_max_envelopes_per_response")]
    pub max_envelopes_per_response: usize,
    /// Server-side: hard ceiling on total envelopes served per single
    /// reconciliation pair (per client request stream). Default
    /// 200_000 = enough for a year of an active channel; stops a
    /// malicious client from inducing an unbounded scan.
    #[serde(default = "default_backfill_total_envelopes_cap")]
    pub total_envelopes_cap: usize,
}

impl Default for BackfillConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_age_days: default_backfill_max_age_days(),
            fanout: default_backfill_fanout(),
            server_max_concurrent_per_peer:
                default_backfill_server_max_concurrent_per_peer(),
            server_max_concurrent_per_channel:
                default_backfill_server_max_concurrent_per_channel(),
            force_resync_if_stale_days: 0,
            max_envelopes_per_response:
                default_backfill_max_envelopes_per_response(),
            total_envelopes_cap: default_backfill_total_envelopes_cap(),
        }
    }
}

fn default_backfill_max_age_days() -> u64 {
    30
}
fn default_backfill_fanout() -> usize {
    3
}
fn default_backfill_server_max_concurrent_per_peer() -> usize {
    4
}
fn default_backfill_server_max_concurrent_per_channel() -> usize {
    1
}
fn default_backfill_max_envelopes_per_response() -> usize {
    1000
}
fn default_backfill_total_envelopes_cap() -> usize {
    200_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KleverConfig {
    /// Klever node RPC URL (user-configured, not hardcoded).
    #[serde(default)]
    pub node_url: String,
    /// Klever API URL (user-configured, not hardcoded).
    #[serde(default)]
    pub api_url: String,
    /// Ogmara KApp smart contract address.
    #[serde(default)]
    pub contract_address: String,
    /// Block scan interval in milliseconds.
    #[serde(default = "default_scan_interval")]
    pub scan_interval_ms: u64,
    /// Block height to start scanning from (skip blocks before SC deployment).
    /// Only used when the chain cursor is 0 (fresh node). Ignored if the node
    /// has already scanned past this block. Default: 0 (scan from genesis).
    #[serde(default)]
    pub start_block: u64,
}

impl Default for KleverConfig {
    fn default() -> Self {
        Self {
            node_url: String::new(),
            api_url: String::new(),
            contract_address: String::new(),
            scan_interval_ms: default_scan_interval(),
            start_block: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfsConfig {
    /// IPFS HTTP API URL.
    #[serde(default = "default_ipfs_api")]
    pub api_url: String,
    /// IPFS gateway URL.
    #[serde(default = "default_ipfs_gateway")]
    pub gateway_url: String,
    /// Max upload size in MB.
    #[serde(default = "default_max_upload")]
    pub max_upload_size_mb: u64,
    /// Auto-generate thumbnails for images/videos.
    #[serde(default = "default_true")]
    pub auto_thumbnail: bool,
    /// Total bytes (in MiB) the media LRU cache may hold across all
    /// entries (spec 4.1, v0.40 tunable). 256 MiB default — fits a few
    /// thousand small thumbnails or a few hundred reasonable images.
    /// Raise for high-readership nodes; lower on small VMs.
    #[serde(default = "default_media_cache_total_mb")]
    pub media_cache_total_mb: u64,
    /// Per-item cap (in MiB) for the media cache. Items larger than
    /// this are never inserted (large videos stream from IPFS instead).
    /// 16 MiB default. Should be smaller than
    /// `media_cache_total_mb` and `max_upload_size_mb`.
    #[serde(default = "default_media_cache_item_mb")]
    pub media_cache_item_mb: u64,
    /// Max concurrent in-flight `/api/v1/media/:cid` handlers. Caps
    /// peak transient RSS from the media endpoint at roughly
    /// `permits * max_upload_size_mb` MiB. Default 32. Lower for
    /// resource-constrained nodes; raise for high-throughput.
    #[serde(default = "default_media_handler_permits")]
    pub media_handler_permits: usize,
    /// Per-client-IP sub-cap on concurrent media handlers (v0.41).
    /// Stops a single IP from grabbing all `media_handler_permits`
    /// slots with slow requests and starving other clients. Defaults
    /// to 4 of the 32 global permits — generous enough that a real
    /// browser opening multiple tabs is fine, tight enough that one
    /// IP can never monopolize the endpoint. Must be > 0 and
    /// <= `media_handler_permits` (validated at config-load).
    #[serde(default = "default_media_per_ip_permits")]
    pub media_per_ip_permits: usize,
    /// Hard cap on the per-IP limiter's tracking map (v0.42).
    /// Bounds memory growth under an adversarial /24-rotation flood
    /// — an attacker burning through millions of source subnets in
    /// the 5 minutes between background sweeps would otherwise
    /// inflate the DashMap to hundreds of MB. At this cap, the
    /// limiter first runs an inline sweep; if still full, new
    /// (untracked) buckets get 503 Service Unavailable until the map
    /// drains. Existing buckets continue normally — legitimate
    /// clients are never displaced. Default 65,536 ≈ 10 MiB resident.
    #[serde(default = "default_media_max_tracked_ips")]
    pub media_max_tracked_ips: usize,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            api_url: default_ipfs_api(),
            gateway_url: default_ipfs_gateway(),
            max_upload_size_mb: default_max_upload(),
            auto_thumbnail: true,
            media_cache_total_mb: default_media_cache_total_mb(),
            media_cache_item_mb: default_media_cache_item_mb(),
            media_handler_permits: default_media_handler_permits(),
            media_per_ip_permits: default_media_per_ip_permits(),
            media_max_tracked_ips: default_media_max_tracked_ips(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// REST/WS API listen address.
    #[serde(default = "default_api_addr")]
    pub listen_addr: String,
    /// REST/WS API listen port (default: 41721).
    #[serde(default = "default_api_port")]
    pub listen_port: u16,
    /// Public URL where this node's API is reachable (e.g. "https://node.ogmara.org").
    /// Used to advertise this node in the network node list.
    #[serde(default)]
    pub public_url: Option<String>,
    /// CORS allowed origins.
    #[serde(default = "default_cors")]
    pub cors_origins: Vec<String>,
    /// Rate limit per IP (requests per minute).
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_ip: u32,
    /// Trusted-proxy CIDRs for client-IP resolution (v0.42).
    ///
    /// When the immediate TCP peer matches one of these CIDRs (or is
    /// loopback, which is always implicitly trusted), the node walks
    /// the `Forwarded` / `X-Forwarded-For` header right-to-left,
    /// skipping addresses that are themselves trusted proxies, and
    /// reports the first untrusted address as the real client.
    ///
    /// Each entry is a CIDR string (`"10.0.0.0/8"`,
    /// `"2001:db8::/32"`) or a bare host address (`"192.0.2.5"`,
    /// `"::1"`). Validated at config-load; a malformed entry aborts
    /// startup rather than silently degrade to "trust nothing extra"
    /// (which would change the security model from "behaves as
    /// configured" to "behaves as misconfigured").
    ///
    /// Leave empty for the default single-host setup (Apache on
    /// loopback in front of L2). Add CDN/edge ranges for multi-hop
    /// CDN deployments where forwarding-header trust must extend
    /// past the immediate proxy.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Proof-of-Work anti-spam configuration.
    #[serde(default)]
    pub pow: PowConfig,
    /// Admin API configuration.
    #[serde(default)]
    pub admin: AdminConfig,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_api_addr(),
            listen_port: default_api_port(),
            public_url: None,
            cors_origins: default_cors(),
            rate_limit_per_ip: default_rate_limit(),
            trusted_proxies: Vec::new(),
            pow: PowConfig::default(),
            admin: AdminConfig::default(),
        }
    }
}

/// Proof-of-Work anti-spam configuration.
///
/// New wallets must solve a SHA-256 hash puzzle before their first message
/// is accepted. On-chain registered wallets and wallets that already solved
/// a challenge are exempt. The difficulty is measured in leading zero bits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowConfig {
    /// Enable PoW challenges for unknown wallets.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Difficulty: number of leading zero bits required in the hash.
    /// 20 bits ≈ ~1M hashes ≈ 2-3 seconds on a phone.
    #[serde(default = "default_pow_difficulty")]
    pub difficulty: u8,
    /// Challenge TTL in seconds (default: 300 = 5 minutes).
    #[serde(default = "default_pow_ttl")]
    pub challenge_ttl_seconds: u64,
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            difficulty: default_pow_difficulty(),
            challenge_ttl_seconds: default_pow_ttl(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    /// Enable admin API.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Serve built-in admin dashboard.
    #[serde(default = "default_true")]
    pub dashboard: bool,
    /// Wallet addresses authorized for remote dashboard access.
    /// Empty list = localhost-only (no auth required from localhost).
    #[serde(default)]
    pub admin_wallets: Vec<String>,
    /// Session token lifetime in hours (default: 24).
    #[serde(default = "default_24")]
    pub session_ttl_hours: u64,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dashboard: true,
            admin_wallets: Vec::new(),
            session_ttl_hours: 24,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage engine (only "rocksdb" supported).
    #[serde(default = "default_engine")]
    pub engine: String,
    /// Maximum database size in GB.
    #[serde(default = "default_max_db_size")]
    pub max_db_size_gb: u64,
    /// Channels to always keep data for.
    #[serde(default)]
    pub pinned_channels: Vec<u64>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            engine: default_engine(),
            max_db_size_gb: default_max_db_size(),
            pinned_channels: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Cache TTL in seconds (0 = no expiry).
    #[serde(default = "default_cache_ttl")]
    pub ttl_seconds: u64,
    /// Max cache size in MB.
    #[serde(default = "default_cache_size")]
    pub max_size_mb: u64,
    /// Auto-pin channels on user interaction.
    #[serde(default = "default_true")]
    pub auto_pin_on_interaction: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: default_cache_ttl(),
            max_size_mb: default_cache_size(),
            auto_pin_on_interaction: true,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PushGatewayConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: String,
    #[serde(default, skip_serializing)]
    pub auth_token: String,
}

impl std::fmt::Debug for PushGatewayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushGatewayConfig")
            .field("enabled", &self.enabled)
            .field("url", &self.url)
            .field("auth_token", &if self.auth_token.is_empty() { "<none>" } else { "<redacted>" })
            .finish()
    }
}

impl Default for PushGatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            auth_token: String::new(),
        }
    }
}

/// State anchoring configuration.
///
/// When enabled, the node periodically computes a Merkle root of L2 state
/// and submits it to the Klever blockchain via the Ogmara KApp smart contract.
#[derive(Clone, Serialize, Deserialize)]
pub struct AnchoringConfig {
    /// Enable periodic state anchoring to the Klever blockchain.
    #[serde(default)]
    pub enabled: bool,
    /// Anchoring interval in seconds (default: 3600 = ~24 anchors/day).
    #[serde(default = "default_anchor_interval")]
    pub interval_seconds: u64,
    /// Optional: hex-encoded 32-byte Ed25519 private key for the anchor wallet.
    /// If absent (or empty string), uses the node's identity key. The
    /// corresponding klv1... address must be registered on the smart contract
    /// via `registerNode` (spec 12 §2.3).
    ///
    /// **Security:** Prefer the `OGMARA_ANCHOR_WALLET_KEY` environment variable
    /// over putting the key in the config file. The key must be on-disk if
    /// `pause_on_shutdown = true` — the SIGTERM handler signs `pauseNode` from
    /// this key without operator interaction.
    ///
    /// **Residency:** the field is wrapped in [`secrecy::SecretString`] so the
    /// hex-string source is zeroized on drop and redacted by `Debug` /
    /// log-formatting paths. `Serialize` is intentionally skipped — the field
    /// must never round-trip through any config-dump output. Consumers reach
    /// the inner `&str` via [`SecretString::expose_secret`] at the two
    /// signing-key derivation callsites only (v0.46.0 Phase C / plan C1).
    /// Empty-string TOML values deserialize to `None`, mirroring pre-0.46.0
    /// behavior where empty meant absent.
    #[serde(default, deserialize_with = "deserialize_wallet_key", skip_serializing)]
    pub wallet_key: Option<SecretString>,
    /// v0.45.0 (spec 13 §6.3): if `true`, the SIGTERM handler signs and
    /// broadcasts a `pauseNode` TX before exit, signaling to other
    /// nodes + clients that this anchorer is going offline gracefully.
    /// Requires `wallet_key` set (env or config) — otherwise the
    /// handler logs a warn and exits without pausing.
    ///
    /// Default false. Enabling this is opt-in because it broadens the
    /// wallet-key threat surface: instead of the key only being used
    /// once-per-hour by the anchoring loop, it's also held in process
    /// memory for shutdown signing. See spec 13 §6.3 wallet-safety
    /// note + the v0.45.0 security audit.
    ///
    /// **Restart required for changes:** this flag is read once at
    /// node startup and cloned into `AppState`. Toggling it in the
    /// config file (and sending SIGHUP, or relying on any reload
    /// flow) does NOT update the in-process value — the SIGTERM
    /// handler continues to use whatever was set when the process
    /// started. Operators must restart the node for a change to
    /// take effect. v0.46.0 Phase B3 surfaces this as a banner in
    /// the dashboard Pause card; the live-reload refactor is
    /// deliberately out-of-scope (plan OPEN 3 resolution 2026-05-17).
    #[serde(default)]
    pub pause_on_shutdown: bool,
    /// v0.45.0 (spec 12 §2.10): optional metadata publication for
    /// on-chain peer discovery (spec 13 §4.3 / §6.1).
    #[serde(default)]
    pub metadata: AnchorMetadataConfig,
}

impl std::fmt::Debug for AnchoringConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `<configured>` rather than `<redacted>` — distinguishes
        // "operator set the field, value hidden" from `<none>` ("field
        // absent, no key configured"). The wrapped `SecretString`'s own
        // Debug impl is also redacting, but we keep the manual line for
        // a uniform two-state representation.
        f.debug_struct("AnchoringConfig")
            .field("enabled", &self.enabled)
            .field("interval_seconds", &self.interval_seconds)
            .field(
                "wallet_key",
                &if self.wallet_key.is_some() { "<configured>" } else { "<none>" },
            )
            .field("pause_on_shutdown", &self.pause_on_shutdown)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl Default for AnchoringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_seconds: default_anchor_interval(),
            wallet_key: None,
            pause_on_shutdown: false,
            metadata: AnchorMetadataConfig::default(),
        }
    }
}

/// Field-level custom deserializer for `AnchoringConfig.wallet_key`.
/// Accepts a TOML string; empty string maps to `None` (preserves the
/// pre-0.46.0 contract where `wallet_key = ""` and an absent field
/// both meant "use the node identity key"); non-empty wraps in
/// `SecretString` so the source is zeroized on drop.
///
/// The `#[serde(default)]` on the field handles the absent-field case
/// without invoking this function; this is only called when TOML
/// actually contains `wallet_key = "..."`.
///
/// **Residency note (Phase C Security Audit N1):** between the
/// `String::deserialize` call and `SecretString::from(s)` consuming
/// the owned `String`, the hex value briefly lives in a plain heap
/// allocation. `SecretString::from(String)` calls `into_boxed_str()`
/// which reuses the allocation when `capacity == len` but reallocates
/// + copies otherwise — the discarded allocation is freed without
/// zeroize. The window is brief and the threat model already assumes
/// config-file confidentiality on disk (an attacker with heap-residue
/// access typically also has the config), so we accept this gap. The
/// env-var path in `Node::run` has the same property by construction.
fn deserialize_wallet_key<'de, D>(deserializer: D) -> Result<Option<SecretString>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(if s.is_empty() {
        None
    } else {
        Some(SecretString::from(s))
    })
}

/// Convenience accessor — returns `Some(&str)` for the hex-encoded key
/// when configured, `None` when absent. Crosses the `ExposeSecret`
/// boundary so callers don't need to handle the `secrecy` type
/// directly. The returned `&str` borrows from the `SecretString`'s
/// internal `Box<str>` and lives for the lifetime of the `AnchoringConfig`
/// reference.
impl AnchoringConfig {
    pub fn wallet_key_hex(&self) -> Option<&str> {
        self.wallet_key.as_ref().map(|s| s.expose_secret())
    }
}

/// Optional on-chain metadata publication for the anchorer wallet
/// (spec 12 §2.10 `setNodeMetadata`).
///
/// Opt-in (`publish = false` by default) because spec 13 §6.2 treats
/// non-publication as a first-class operator profile — operators can
/// register + anchor without ever appearing in `getActiveNodes` for
/// privacy / regulatory-resilience reasons.
///
/// When `publish = true` and `multiaddrs = []`, the node auto-derives
/// a multiaddr from `[network] listen_port` + `[api] public_url` so
/// the operator doesn't have to hand-construct the string. Operators
/// with non-trivial topology (NAT, anonymizer front, onion) set
/// `multiaddrs` explicitly instead.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnchorMetadataConfig {
    /// Opt-in flag. Default false — node anchors silently without
    /// appearing in `getActiveNodes`.
    #[serde(default)]
    pub publish: bool,
    /// Explicit multiaddr list (≤ 8 entries, each ≤ 256 bytes per
    /// SC caps). When empty AND `publish = true`, the node
    /// auto-derives a single multiaddr from `[api] public_url`.
    #[serde(default)]
    pub multiaddrs: Vec<String>,
}

/// Snapshot bootstrap configuration (spec 11-snapshot-sync.md).
///
/// Controls peer-to-peer state snapshots: a serving node periodically caches
/// a Merkle-rooted summary of its SC-derived state (users, channels, anchors)
/// so new nodes can bootstrap without scanning millions of Klever blocks.
///
/// **Phase 1 (v0.34):** serve-only — caches a manifest and serves chunks on request.
/// **Phase 2 (v0.35):** opt-in client fetch + quorum + apply path.
/// **Phase 3 (v0.36):** anchor re-verification against Klever; default-on bootstrap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    // --- Serving (Phase 1+) ---
    /// Whether this node advertises and serves snapshots to peers.
    /// Disable on resource-constrained nodes to skip the periodic cache build.
    #[serde(default = "default_true")]
    pub serve_enabled: bool,
    /// How often to rebuild the cached snapshot from live storage (seconds).
    /// 3600 = once per hour. Lower values are wasteful; higher values mean
    /// fresh joiners replay more blocks after applying the snapshot.
    #[serde(default = "default_snapshot_rebuild_interval")]
    pub serve_rebuild_interval_secs: u64,
    /// Target chunk size in bytes for the per-CF byte stream (default 4 MiB).
    /// Smaller chunks = more parallelism but more overhead; larger = fewer
    /// requests but heavier failure-retry cost.
    #[serde(default = "default_snapshot_chunk_size")]
    pub chunk_size_bytes: u32,
    /// Maximum in-flight chunk responses across all peers. Throttles outbound
    /// bandwidth when many peers are simultaneously bootstrapping.
    #[serde(default = "default_snapshot_max_concurrent")]
    pub serve_max_concurrent_requests: u32,

    // --- Bootstrap / receive (Phase 2+) ---
    /// Whether to fetch a snapshot at startup if conditions are met.
    /// **Defaults to `true` in v0.36+** — Phase 3 added anchor
    /// re-verification against Klever AND producer signature
    /// verification, making the apply path safe to run by default on
    /// fresh nodes. Set to `false` to keep the legacy block-by-block
    /// scan from `start_block`.
    #[serde(default = "default_true")]
    pub bootstrap_enabled: bool,
    /// Only attempt bootstrap when the chain cursor is "fresh" — either zero,
    /// or below the configured `klever.start_block`. Prevents accidentally
    /// rewriting a healthy node's state if `bootstrap_enabled` is flipped on.
    #[serde(default = "default_true")]
    pub bootstrap_only_if_fresh: bool,
    /// Permit applying a snapshot onto a non-empty node (i.e., not fresh
    /// per `bootstrap_only_if_fresh`). Dangerous — the apply path clears
    /// snapshot-domain CFs before writing chunks. Default false.
    #[serde(default)]
    pub allow_apply_over_existing: bool,
    /// Total peers to sample for snapshot quorum.
    #[serde(default = "default_snapshot_quorum_sample")]
    pub quorum_sample_size: u32,
    /// Minimum peers that must agree on the snapshot root before accepting.
    #[serde(default = "default_snapshot_quorum_min")]
    pub quorum_min_peers: u32,
    /// Number of mirrors to fetch chunks from in parallel (clamped to the
    /// number of agreeing peers actually available).
    #[serde(default = "default_snapshot_parallel_fetches")]
    pub parallel_fetches: u32,
    /// Per-chunk retry budget across all mirrors before aborting bootstrap.
    #[serde(default = "default_snapshot_chunk_retries")]
    pub chunk_retries: u32,
    /// How long to wait for snapshot-capable peers before giving up
    /// and falling back to a full chain scan (seconds).
    #[serde(default = "default_snapshot_discovery_timeout")]
    pub discovery_timeout_secs: u64,
    /// Per-request timeout for `Advertise` and `GetManifest` (seconds).
    #[serde(default = "default_snapshot_manifest_timeout")]
    pub manifest_timeout_secs: u64,
    /// Per-request timeout for `GetChunk` (seconds).
    #[serde(default = "default_snapshot_chunk_timeout")]
    pub chunk_timeout_secs: u64,
    /// Hard cap on a single snapshot's combined uncompressed bytes
    /// (sum of `CfManifest.total_bytes`). Reject manifests beyond this.
    #[serde(default = "default_snapshot_max_total_bytes")]
    pub max_total_bytes: u64,
    /// **DANGEROUS — TESTNET / SMALL-NETWORK ONLY.** Skip the Klever
    /// `getStateRoot` re-verification of every anchor in the received
    /// snapshot before applying it.
    ///
    /// Phase 3 (v0.36) made anchor verification mandatory because in a
    /// real multi-anchorer network it's the strongest defense against
    /// a malicious snapshot producer — `getStateRoot` returns only the
    /// quorum-canonical root (`ANCHOR_QUORUM_MIN` = 3 distinct
    /// anchorers must agree on the same root for any given height
    /// before the SC promotes it to canonical). On a single-anchorer
    /// testnet that threshold can never be satisfied → `getStateRoot`
    /// always returns "Anchor not found" → the receiver's
    /// anti-downgrade ratchet (audit Sec W1) trips after >2 newer
    /// NotAnchored claims and the apply is refused.
    ///
    /// Setting this flag to `true` short-circuits the entire anchor
    /// loop. The receiver still verifies quorum (the snapshot root
    /// must be agreed by `quorum_min_peers` peers), Merkle (every
    /// chunk hash-checked + rolled up to the manifest's
    /// `snapshot_root`), and the producer's Ed25519 signature. What
    /// is given up is the on-chain truth check — if your single
    /// trusted producer is dishonest, you have no Klever-based
    /// independent witness.
    ///
    /// Use this exclusively on networks where you control every
    /// participant and the SC's quorum precondition is genuinely
    /// unsatisfiable. Production deployments must leave this `false`
    /// (the default). A loud warning is logged at startup whenever
    /// it is `true`.
    #[serde(default)]
    pub experimental_skip_anchor_verify: bool,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            serve_enabled: true,
            serve_rebuild_interval_secs: default_snapshot_rebuild_interval(),
            chunk_size_bytes: default_snapshot_chunk_size(),
            serve_max_concurrent_requests: default_snapshot_max_concurrent(),
            bootstrap_enabled: true,
            bootstrap_only_if_fresh: true,
            allow_apply_over_existing: false,
            quorum_sample_size: default_snapshot_quorum_sample(),
            quorum_min_peers: default_snapshot_quorum_min(),
            parallel_fetches: default_snapshot_parallel_fetches(),
            chunk_retries: default_snapshot_chunk_retries(),
            discovery_timeout_secs: default_snapshot_discovery_timeout(),
            manifest_timeout_secs: default_snapshot_manifest_timeout(),
            chunk_timeout_secs: default_snapshot_chunk_timeout(),
            max_total_bytes: default_snapshot_max_total_bytes(),
            experimental_skip_anchor_verify: false,
        }
    }
}

fn default_snapshot_rebuild_interval() -> u64 { 3600 }
fn default_snapshot_chunk_size() -> u32 { 4 * 1024 * 1024 }
fn default_snapshot_max_concurrent() -> u32 { 8 }
fn default_snapshot_quorum_sample() -> u32 { 5 }
fn default_snapshot_quorum_min() -> u32 { 3 }
fn default_snapshot_parallel_fetches() -> u32 { 3 }
fn default_snapshot_chunk_retries() -> u32 { 5 }
fn default_snapshot_discovery_timeout() -> u64 { 30 }
fn default_snapshot_manifest_timeout() -> u64 { 10 }
fn default_snapshot_chunk_timeout() -> u64 { 60 }
fn default_snapshot_max_total_bytes() -> u64 { 2 * 1024 * 1024 * 1024 } // 2 GiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log format: json or pretty.
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub telegram: TelegramAlertConfig,
    #[serde(default)]
    pub discord: DiscordAlertConfig,
    #[serde(default)]
    pub webhook: WebhookAlertConfig,
    /// Post alerts to an Ogmara channel using a wallet identity.
    #[serde(default)]
    pub ogmara_channel: OgmaraChannelAlertConfig,
    #[serde(default)]
    pub thresholds: AlertThresholds,
    #[serde(default)]
    pub cooldown: AlertCooldown,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            telegram: TelegramAlertConfig::default(),
            discord: DiscordAlertConfig::default(),
            webhook: WebhookAlertConfig::default(),
            ogmara_channel: OgmaraChannelAlertConfig::default(),
            thresholds: AlertThresholds::default(),
            cooldown: AlertCooldown::default(),
        }
    }
}

/// Configuration for posting alerts to an Ogmara channel (spec 10-dashboard.md §9.4).
///
/// The configured wallet must already be a member of the target channel
/// (joined via a client app before enabling this feature).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OgmaraChannelAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Target channel ID (see spec 10-dashboard.md §2.2 for retrieval).
    #[serde(default)]
    pub channel_id: u64,
    /// Klever address (klv1...) to post alerts as.
    #[serde(default)]
    pub wallet_address: String,
    /// Path to Ed25519 private key file. Prefer OGMARA_ALERT_SIGNING_KEY env var.
    #[serde(default, skip_serializing)]
    pub signing_key_path: String,
}

/// Metrics collection configuration (spec 10-dashboard.md §10.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// System metrics sampling interval in seconds.
    #[serde(default = "default_10")]
    pub system_interval_seconds: u64,
    /// IPFS metrics polling interval in seconds.
    #[serde(default = "default_30")]
    pub ipfs_interval_seconds: u64,
    /// Storage metrics polling interval in seconds.
    #[serde(default = "default_60")]
    pub storage_interval_seconds: u64,
    /// Ring buffer capacity (1-minute snapshots to retain).
    #[serde(default = "default_1440")]
    pub history_capacity: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            system_interval_seconds: 10,
            ipfs_interval_seconds: 30,
            storage_interval_seconds: 60,
            history_capacity: 1440,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct TelegramAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Loaded from environment variable in production. Never put in config file.
    #[serde(default, skip_serializing)]
    pub bot_token: String,
    #[serde(default)]
    pub chat_id: String,
}

impl std::fmt::Debug for TelegramAlertConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramAlertConfig")
            .field("enabled", &self.enabled)
            .field("bot_token", &if self.bot_token.is_empty() { "<none>" } else { "<redacted>" })
            .field("chat_id", &self.chat_id)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct DiscordAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Loaded from environment variable in production. Never put in config file.
    #[serde(default, skip_serializing)]
    pub webhook_url: String,
}

impl std::fmt::Debug for DiscordAlertConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscordAlertConfig")
            .field("enabled", &self.enabled)
            .field("webhook_url", &if self.webhook_url.is_empty() { "<none>" } else { "<redacted>" })
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebhookAlertConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    #[serde(default = "default_60")]
    pub klever_disconnect_seconds: u64,
    #[serde(default = "default_30")]
    pub ipfs_disconnect_seconds: u64,
    #[serde(default = "default_3")]
    pub min_peers: u32,
    #[serde(default = "default_90")]
    pub max_disk_usage_percent: u8,
    #[serde(default = "default_85")]
    pub max_memory_usage_percent: u8,
    #[serde(default = "default_anchor_overdue")]
    pub anchor_overdue_multiplier: f64,
    #[serde(default = "default_100_u64")]
    pub sc_sync_max_lag_blocks: u64,
    #[serde(default = "default_100_u32")]
    pub rate_limit_alert_per_min: u32,
    #[serde(default = "default_50")]
    pub failed_sig_alert_per_min: u32,
    /// Number of consecutive canonicalized heights at which the local
    /// computed root must differ from the on-chain canonical root
    /// before the `anchor_divergence` alert fires (spec 12 §6.1,
    /// spec 10 §9.2). Default 2 — one mismatch could be transient,
    /// two consecutive is a real divergence signal.
    #[serde(default = "default_anchor_divergence_consecutive")]
    pub anchor_divergence_consecutive: u32,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            klever_disconnect_seconds: 60,
            ipfs_disconnect_seconds: 30,
            min_peers: 3,
            max_disk_usage_percent: 90,
            max_memory_usage_percent: 85,
            anchor_overdue_multiplier: 2.0,
            sc_sync_max_lag_blocks: 100,
            rate_limit_alert_per_min: 100,
            failed_sig_alert_per_min: 50,
            anchor_divergence_consecutive: default_anchor_divergence_consecutive(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCooldown {
    /// Minimum seconds between repeated alerts of the same type.
    #[serde(default = "default_300")]
    pub seconds: u64,
}

impl Default for AlertCooldown {
    fn default() -> Self {
        Self { seconds: 300 }
    }
}

// --- Default value functions ---

fn default_listen_port() -> u16 {
    41720
}
fn default_max_peers() -> u32 {
    50
}
fn default_bootstrap_nodes() -> Vec<String> {
    // Empty default — SC-driven discovery (tier 3 per spec 13 §4.3) is
    // the primary boot path from l2-node 0.46.5+. Operators with a
    // non-empty `bootstrap_nodes` list run in hybrid mode (explicit
    // peers + SC supplementary); operators with both empty and
    // `network.sc_discovery.enabled = false` run an isolated subnet
    // (validated at config-load — see `validate`).
    Vec::new()
}
fn default_scan_interval() -> u64 {
    3000
}
fn default_ipfs_api() -> String {
    "http://127.0.0.1:5001".to_string()
}
fn default_ipfs_gateway() -> String {
    "http://127.0.0.1:8080".to_string()
}
fn default_max_upload() -> u64 {
    50
}
fn default_media_cache_total_mb() -> u64 {
    256
}
fn default_media_cache_item_mb() -> u64 {
    16
}
fn default_media_handler_permits() -> usize {
    32
}
fn default_media_per_ip_permits() -> usize {
    4
}
fn default_media_max_tracked_ips() -> usize {
    65_536
}
fn default_api_addr() -> String {
    "127.0.0.1".to_string()
}
fn default_api_port() -> u16 {
    41721
}
fn default_cors() -> Vec<String> {
    // Includes `https://ogmara.org` so the public network page
    // (`ogmara.org/network.html`) can run its browser-side
    // reachability probe against a fresh node out of the box.
    // Without it, an operator who runs the tutorial and lists their
    // node via presence-gossip gets a red "unreachable" dot purely
    // because the cross-origin probe is blocked by CORS — even though
    // the API is otherwise serving correctly. Operators who want a
    // narrower origin policy can remove this entry.
    vec![
        "https://ogmara.org".to_string(),
        "http://localhost:*".to_string(),
    ]
}
fn default_rate_limit() -> u32 {
    100
}
fn default_pow_difficulty() -> u8 {
    20
}
fn default_pow_ttl() -> u64 {
    300
}
fn default_engine() -> String {
    "rocksdb".to_string()
}
fn default_max_db_size() -> u64 {
    50
}
fn default_cache_ttl() -> u64 {
    86400
}
fn default_cache_size() -> u64 {
    1024
}
fn default_anchor_interval() -> u64 {
    3600
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "json".to_string()
}
fn default_true() -> bool {
    true
}
fn default_60() -> u64 {
    60
}
fn default_30() -> u64 {
    30
}
fn default_3() -> u32 {
    3
}
fn default_90() -> u8 {
    90
}
fn default_85() -> u8 {
    85
}
fn default_anchor_divergence_consecutive() -> u32 {
    2
}

fn default_anchor_overdue() -> f64 {
    2.0
}
fn default_100_u64() -> u64 {
    100
}
fn default_100_u32() -> u32 {
    100
}
fn default_50() -> u32 {
    50
}
fn default_300() -> u64 {
    300
}
fn default_10() -> u64 {
    10
}
fn default_24() -> u64 {
    24
}
fn default_1440() -> u64 {
    1440
}

/// Detect network ID from a Klever node URL.
///
/// Returns "testnet" if the URL contains "testnet", otherwise "mainnet".
/// This is the safe default: unknown URLs are treated as mainnet to prevent
/// testnet nodes from accidentally peering with mainnet.
fn detect_network_id(node_url: &str) -> String {
    if node_url.contains("testnet") {
        "testnet".to_string()
    } else {
        "mainnet".to_string()
    }
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut config: Config =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
        config.apply_migrations();
        config.validate()?;
        Ok(config)
    }

    /// Apply runtime migrations for configs created by older versions.
    ///
    /// This ensures existing node operators get critical defaults (like
    /// `network_id` auto-detection) without manually editing their config
    /// files after upgrades.
    fn apply_migrations(&mut self) {
        // NOTE: prior versions (<0.46.5) auto-filled an empty
        // `bootstrap_nodes` with the legacy `node.ogmara.org` seed list.
        // That migration is removed in 0.46.5 because empty is now the
        // intentional default — it triggers pure SC-driven discovery
        // (spec 13 §4.2 / §4.3). Existing operators with an explicit
        // legacy entry in their config.toml retain it (hybrid mode);
        // operators who relied on the previous auto-fill behaviour
        // transition into pure SC discovery on first 0.46.5 boot.

        // Migration: auto-detect network_id from klever.node_url if not set.
        // Configs created before v0.28.0 have no network_id field.
        if self.network.network_id.is_none() {
            let detected = detect_network_id(&self.klever.node_url);
            tracing::info!(
                network_id = %detected,
                "Config migration: auto-detected network_id from klever.node_url"
            );
            self.network.network_id = Some(detected);
        }
    }

    /// Return the resolved network ID (always present after apply_migrations).
    pub fn network_id(&self) -> &str {
        self.network.network_id.as_deref().unwrap_or("mainnet")
    }

    /// Validate the configuration for consistency.
    ///
    /// Audit Phase 3 Sec W3: snapshot bootstrap (default-on in v0.36+)
    /// relies on Klever's `getStateRoot(block_height)` view for anchor
    /// re-verification — the entire trust model of the apply path. If
    /// `klever.node_url` is plain HTTP an on-path attacker can serve
    /// fabricated `getStateRoot` responses that match a poisoned
    /// snapshot. We warn (not hard-error) at config load so operators
    /// notice; a future version will refuse non-HTTPS outright.
    fn warn_if_non_https_klever_url(&self) {
        let url = self.klever.node_url.trim();
        if url.is_empty() {
            return;
        }
        // Allow localhost / 127.0.0.1 / private LAN URLs (often used in
        // dev / WireGuard setups where TLS terminates elsewhere).
        let is_local = url.starts_with("http://localhost")
            || url.starts_with("http://127.")
            || url.starts_with("http://10.")
            || url.starts_with("http://192.168.")
            || url.starts_with("http://[::1]");
        if url.starts_with("http://") && !is_local {
            tracing::warn!(
                klever_node_url = %url,
                "Snapshot bootstrap re-verifies anchors via Klever RPC. \
                 Using a non-HTTPS klever.node_url lets an on-path attacker forge \
                 getStateRoot responses that match a poisoned snapshot. \
                 Set https:// before enabling snapshot.bootstrap_enabled in production."
            );
        }
    }

    pub fn validate(&mut self) -> Result<()> {
        self.warn_if_non_https_klever_url();
        // Spec 13 §4.2 (l2-node 0.46.5+): refuse to start in the
        // both-empty case. An operator with `bootstrap_nodes = []` AND
        // `sc_discovery.enabled = false` has no way to discover peers
        // at all — the node would idle silently, never joining any
        // network. Fail loudly with a config-fix pointer instead.
        if self.network.bootstrap_nodes.is_empty() && !self.network.sc_discovery.enabled {
            anyhow::bail!(
                "network.bootstrap_nodes = [] AND network.sc_discovery.enabled = false: \
                 no way to discover peers. Either (a) leave sc_discovery.enabled = true \
                 (default) so the node discovers peers from the on-chain registry, or \
                 (b) populate bootstrap_nodes with explicit peer multiaddrs for an \
                 isolated subnet. See docs/specs/13-node-discovery.md §4.2 for the \
                 three supported modes."
            );
        }
        // Spec 13 §4.2: an operator typo of `retry_interval_secs = 0`
        // would yield `tokio::time::sleep(Duration::ZERO)` in the
        // cold-start retry loop and a hot-spin against the Klever
        // endpoint at full thread speed (Security Audit W2, 0.46.5).
        // Floor at 5 seconds — fast enough for any realistic
        // bootstrap recovery, slow enough to never melt an RPC.
        const MIN_SC_DISCOVERY_RETRY_SECS: u64 = 5;
        if self.network.sc_discovery.retry_interval_secs < MIN_SC_DISCOVERY_RETRY_SECS {
            anyhow::bail!(
                "network.sc_discovery.retry_interval_secs = {} is too small \
                 (minimum {} seconds — values lower would hot-spin the SC RPC). \
                 Default is 60.",
                self.network.sc_discovery.retry_interval_secs,
                MIN_SC_DISCOVERY_RETRY_SECS,
            );
        }
        // Code Audit W2: a `max_candidates = 0` would otherwise be
        // silently clamped at construction time. Reject loudly so
        // operator misconfiguration surfaces at config-load.
        if self.network.sc_discovery.max_candidates == 0 {
            anyhow::bail!(
                "network.sc_discovery.max_candidates must be > 0 (default is 5)"
            );
        }
        // Spec 3 §media-fetch (l2-node 0.46.7+) — media peer-fallback
        // tunables. Zero values would either deadlock (fanout=0 fans
        // out to nothing) or hot-spin (timeouts=0 fail immediately).
        // Hard ceilings prevent operator misconfig from amplifying
        // load onto the peer mesh.
        if self.media.peer_fallback_enabled {
            if self.media.peer_fallback_fanout == 0 {
                anyhow::bail!(
                    "media.peer_fallback_fanout must be > 0 when \
                     peer_fallback_enabled = true (default is 3)"
                );
            }
            const MAX_MEDIA_PEER_FALLBACK_FANOUT: usize = 16;
            if self.media.peer_fallback_fanout > MAX_MEDIA_PEER_FALLBACK_FANOUT {
                anyhow::bail!(
                    "media.peer_fallback_fanout = {} exceeds the cap of {} \
                     (per-fetch amplification — reduce or disable)",
                    self.media.peer_fallback_fanout,
                    MAX_MEDIA_PEER_FALLBACK_FANOUT
                );
            }
            if self.media.peer_fallback_connect_timeout_secs == 0 {
                anyhow::bail!(
                    "media.peer_fallback_connect_timeout_secs must be > 0 \
                     (default is 5)"
                );
            }
            if self.media.peer_fallback_read_timeout_secs == 0 {
                anyhow::bail!(
                    "media.peer_fallback_read_timeout_secs must be > 0 \
                     (default is 30)"
                );
            }
            if self.media.peer_fallback_global_concurrent == 0 {
                anyhow::bail!(
                    "media.peer_fallback_global_concurrent must be > 0 \
                     (default is 16)"
                );
            }
            const MAX_MEDIA_PEER_FALLBACK_GLOBAL: usize = 256;
            if self.media.peer_fallback_global_concurrent
                > MAX_MEDIA_PEER_FALLBACK_GLOBAL
            {
                anyhow::bail!(
                    "media.peer_fallback_global_concurrent = {} exceeds the \
                     cap of {} (global outbound footprint — reduce)",
                    self.media.peer_fallback_global_concurrent,
                    MAX_MEDIA_PEER_FALLBACK_GLOBAL
                );
            }
            if self.media.peer_fallback_candidate_cache_secs == 0 {
                anyhow::bail!(
                    "media.peer_fallback_candidate_cache_secs must be > 0 \
                     — would hammer the SC RPC on every fallback fetch \
                     (default is 300)"
                );
            }
        }
        // Spec 1 §channel-history-reconciliation (l2-node 0.47.0+).
        if self.backfill.enabled {
            if self.backfill.fanout == 0 {
                anyhow::bail!(
                    "backfill.fanout must be > 0 when enabled (default 3)"
                );
            }
            const MAX_BACKFILL_FANOUT: usize = 16;
            if self.backfill.fanout > MAX_BACKFILL_FANOUT {
                anyhow::bail!(
                    "backfill.fanout = {} exceeds cap of {} (amplification \
                     — reduce or disable)",
                    self.backfill.fanout,
                    MAX_BACKFILL_FANOUT
                );
            }
            if self.backfill.server_max_concurrent_per_peer == 0 {
                anyhow::bail!(
                    "backfill.server_max_concurrent_per_peer must be > 0 \
                     (default 4)"
                );
            }
            if self.backfill.server_max_concurrent_per_channel == 0 {
                anyhow::bail!(
                    "backfill.server_max_concurrent_per_channel must be > 0 \
                     (default 1)"
                );
            }
            if self.backfill.max_envelopes_per_response == 0 {
                anyhow::bail!(
                    "backfill.max_envelopes_per_response must be > 0 \
                     (default 1000)"
                );
            }
            const MAX_ENVELOPES_PER_RESPONSE_CEILING: usize = 50_000;
            if self.backfill.max_envelopes_per_response
                > MAX_ENVELOPES_PER_RESPONSE_CEILING
            {
                anyhow::bail!(
                    "backfill.max_envelopes_per_response = {} exceeds the \
                     ceiling of {} (single libp2p response cap is ~10 MiB \
                     CBOR; large batches cause memory spikes on the \
                     receiver)",
                    self.backfill.max_envelopes_per_response,
                    MAX_ENVELOPES_PER_RESPONSE_CEILING
                );
            }
            if self.backfill.total_envelopes_cap == 0 {
                anyhow::bail!(
                    "backfill.total_envelopes_cap must be > 0 (default \
                     200000)"
                );
            }
            if self.backfill.max_age_days == 0 {
                anyhow::bail!(
                    "backfill.max_age_days must be > 0 when enabled — use \
                     `force_resync_if_stale_days = 0` to disable \
                     re-reconciliation, or `enabled = false` to disable \
                     backfill entirely"
                );
            }
        }
        // Spec 13 §6.4 (l2-node 0.46.9+) — onion-transport surface.
        // We only check the operator-controlled inputs here; the
        // SOCKS5 dialer module enforces the runtime properties (DNS
        // leak, IP fallthrough).
        if self.network.tor.enabled {
            // socks_proxy must parse as `host:port` AND host must be
            // a loopback address. A remote SOCKS proxy would route
            // every onion connection through that server, which the
            // operator must not unwittingly do — it inverts the
            // deanonymisation model. Operators with a real cross-
            // host SOCKS5 need have a documented future override
            // path; v0.46.9 keeps the rule strict.
            let socks = self.network.tor.socks_proxy.trim();
            let parsed: std::net::SocketAddr = socks.parse().with_context(|| {
                format!(
                    "network.tor.socks_proxy = {:?} must be a valid host:port \
                     SocketAddr (default is 127.0.0.1:9050)",
                    socks
                )
            })?;
            if !parsed.ip().is_loopback() {
                anyhow::bail!(
                    "network.tor.socks_proxy = {} must point at a loopback \
                     address (default 127.0.0.1:9050). A non-loopback SOCKS \
                     proxy would route every onion dial through a remote \
                     server, breaking the deanonymisation model. If you \
                     genuinely need a remote SOCKS proxy, raise an issue \
                     describing the threat model.",
                    parsed
                );
            }
            // Hidden-service hostname format check (v3 onion is
            // 56 base32 chars + ".onion" = 62 chars). Allow empty —
            // operators may enable Tor for outbound only (future release).
            let host = self.network.tor.listen_onion_hostname.trim();
            if !host.is_empty() {
                if !host.is_ascii() {
                    anyhow::bail!(
                        "network.tor.listen_onion_hostname must be ASCII"
                    );
                }
                if !host.ends_with(".onion") {
                    anyhow::bail!(
                        "network.tor.listen_onion_hostname = {:?} must end in \
                         '.onion'",
                        host
                    );
                }
                // v3 onion: 56 base32 + ".onion" — v2 is dead since
                // 2021 (Tor 0.4.6). Refuse anything else.
                let stem = &host[..host.len() - ".onion".len()];
                if stem.len() != 56 || !stem.bytes().all(|b| {
                    matches!(b, b'a'..=b'z' | b'2'..=b'7')
                }) {
                    anyhow::bail!(
                        "network.tor.listen_onion_hostname = {:?} must be a \
                         v3 onion address (56 lowercase-base32 chars + \
                         '.onion'); v2 onions were deprecated by Tor in 2021",
                        host
                    );
                }
                if self.network.tor.listen_onion_port == 0 {
                    anyhow::bail!(
                        "network.tor.listen_onion_port must be > 0 when \
                         listen_onion_hostname is set — the inbound listen \
                         needs a non-zero loopback port for the Tor service \
                         to forward to"
                    );
                }
            }
            // advertise_onion_in_metadata requires a hostname AND a
            // port — refuse the case where advertise is on but no
            // hostname is configured (would advertise an empty
            // multiaddr).
            if self.network.tor.advertise_onion_in_metadata
                && (host.is_empty() || self.network.tor.listen_onion_port == 0)
            {
                anyhow::bail!(
                    "network.tor.advertise_onion_in_metadata = true requires \
                     both listen_onion_hostname and listen_onion_port to be \
                     set — cannot advertise an empty onion multiaddr"
                );
            }
        }
        // Spec 13 §10 (l2-node 0.48.0+) — presence-gossip subsystem
        // tunables. Only checked when `enabled = true` so operators
        // who leave the block untouched / disabled never hit these
        // gates.
        if self.network.presence.enabled {
            // Hard ceiling on record TTL (spec 13 §10.3: max 7 days).
            // A larger value would cause peers to keep stale records
            // indefinitely; the topic-validation hook rejects incoming
            // records that exceed the cap, so a self-configured TTL
            // above the cap would also produce records that our own
            // peers would refuse to relay.
            if self.network.presence.record_ttl_secs == 0 {
                anyhow::bail!(
                    "network.presence.record_ttl_secs must be > 0 when \
                     enabled (default 86400 = 24h)"
                );
            }
            if self.network.presence.record_ttl_secs > PRESENCE_MAX_RECORD_TTL_SECS {
                anyhow::bail!(
                    "network.presence.record_ttl_secs = {} exceeds the \
                     spec 13 §10.3 maximum of {} seconds (7 days). Reduce \
                     record_ttl_secs to {} or less.",
                    self.network.presence.record_ttl_secs,
                    PRESENCE_MAX_RECORD_TTL_SECS,
                    PRESENCE_MAX_RECORD_TTL_SECS,
                );
            }
            // Re-broadcast cadence must be strictly less than
            // `record_ttl_secs / 2` so peers always hold a valid record
            // between re-broadcasts (spec 13 §10.5). Zero would hot-spin
            // the publish loop.
            if self.network.presence.rebroadcast_interval_secs == 0 {
                anyhow::bail!(
                    "network.presence.rebroadcast_interval_secs must be > 0 \
                     when enabled (default 21600 = 6h)"
                );
            }
            let half_ttl = self.network.presence.record_ttl_secs / 2;
            if self.network.presence.rebroadcast_interval_secs >= half_ttl {
                anyhow::bail!(
                    "network.presence.rebroadcast_interval_secs = {} must be \
                     strictly less than network.presence.record_ttl_secs / 2 \
                     ({}). Either lower rebroadcast_interval_secs or raise \
                     record_ttl_secs so peers always hold a valid record \
                     between re-broadcasts (spec 13 §10.5).",
                    self.network.presence.rebroadcast_interval_secs,
                    half_ttl,
                );
            }
            // Denylist entries must parse as libp2p PeerIds. Silent
            // dropping would let an operator typo a PeerId and never
            // notice that the bad operator's records still get cached.
            for (idx, entry) in self.network.presence.denylist.iter().enumerate() {
                if entry.trim().is_empty() {
                    anyhow::bail!(
                        "network.presence.denylist[{}] is empty — remove or \
                         replace with a valid libp2p PeerId (base58)",
                        idx,
                    );
                }
                entry.parse::<libp2p::PeerId>().with_context(|| {
                    format!(
                        "network.presence.denylist[{}] = {:?} must be a \
                         valid libp2p PeerId (base58, e.g. \"12D3KooW...\")",
                        idx, entry,
                    )
                })?;
            }
        }
        if self.network.listen_port == 0 {
            anyhow::bail!("network.listen_port must be > 0");
        }
        if self.api.listen_port == 0 {
            anyhow::bail!("api.listen_port must be > 0");
        }
        if self.api.listen_port == self.network.listen_port {
            anyhow::bail!("api.listen_port and network.listen_port must be different");
        }
        // Validate network_id if explicitly set
        if let Some(ref nid) = self.network.network_id {
            if nid != "mainnet" && nid != "testnet" {
                anyhow::bail!(
                    "network.network_id must be \"mainnet\" or \"testnet\", got \"{}\"",
                    nid
                );
            }
        }
        // Validate media-handler tunables (v0.40). Two classes of check:
        //
        //   HARD REJECTS — values that produce broken runtime behavior:
        //     * zero permits → semaphore deadlocks every request
        //     * zero cache caps → degenerate (cache that holds nothing)
        //     * absurd upper bounds → reverts the v0.39 memory
        //       amplification mitigation
        //
        //   SOFT FIXES — cross-field inconsistencies that DON'T affect
        //   correctness but indicate operator confusion:
        //     * item_mb > total_mb → every cached item evicts everything
        //     * item_mb > max_upload_mb → harmless (items > max_upload
        //       can't enter the system anyway), but suggests the
        //       operator is unaware of the implicit cap
        //
        //   v0.40.1 fix: soft cases now auto-clamp + warn instead of
        //   bailing. Pre-0.40.1 this branch hard-rejected legitimate
        //   pre-v0.40 production configs (e.g. `max_upload_size_mb = 10`
        //   combined with the default `media_cache_item_mb = 16`), which
        //   prevented upgrades. The hard rejects remain to catch values
        //   that actually break runtime.
        if self.ipfs.media_handler_permits == 0 {
            anyhow::bail!("ipfs.media_handler_permits must be > 0 (zero deadlocks the media endpoint)");
        }
        const MAX_MEDIA_PERMITS: usize = 4096;
        if self.ipfs.media_handler_permits > MAX_MEDIA_PERMITS {
            anyhow::bail!(
                "ipfs.media_handler_permits = {} exceeds the safety cap of {}",
                self.ipfs.media_handler_permits,
                MAX_MEDIA_PERMITS
            );
        }
        if self.ipfs.media_cache_total_mb == 0 {
            anyhow::bail!("ipfs.media_cache_total_mb must be > 0");
        }
        if self.ipfs.media_cache_item_mb == 0 {
            anyhow::bail!("ipfs.media_cache_item_mb must be > 0");
        }
        // Per-IP permits (v0.41). HARD reject zero (would 429
        // everyone — endpoint becomes unusable). HARD reject
        // exceeding the global permits (no sub-cap effect; values
        // larger than global silently degrade to "no per-IP cap"
        // which defeats the feature). SOFT clamp the upper bound to
        // global so a misconfigured `per_ip = 9999` with global = 32
        // doesn't fail upgrade — it just gets pulled back to 32.
        if self.ipfs.media_per_ip_permits == 0 {
            anyhow::bail!("ipfs.media_per_ip_permits must be > 0 (zero rejects every media request as 429)");
        }
        if self.ipfs.media_per_ip_permits > self.ipfs.media_handler_permits {
            eprintln!(
                "[config] ipfs.media_per_ip_permits ({}) > ipfs.media_handler_permits ({}); \
                 clamping to {} (per-IP cap can't exceed global cap).",
                self.ipfs.media_per_ip_permits,
                self.ipfs.media_handler_permits,
                self.ipfs.media_handler_permits,
            );
            self.ipfs.media_per_ip_permits = self.ipfs.media_handler_permits;
        }
        // Per-IP tracking map cap (v0.42). HARD reject zero — would
        // make every acquire from an untracked /24 fail-503 (no inline
        // sweep can save it from cap=0). HARD reject absurd ceilings
        // (>16M entries ≈ 2.4 GiB resident) — that's clearly a typo,
        // not a tuning choice. Honest ceilings live well under 1M.
        if self.ipfs.media_max_tracked_ips == 0 {
            anyhow::bail!(
                "ipfs.media_max_tracked_ips must be > 0 (zero would 503 every new client)",
            );
        }
        const MAX_TRACKED_IPS_CEILING: usize = 16_777_216; // 2^24
        if self.ipfs.media_max_tracked_ips > MAX_TRACKED_IPS_CEILING {
            anyhow::bail!(
                "ipfs.media_max_tracked_ips = {} exceeds the safety ceiling of {} entries",
                self.ipfs.media_max_tracked_ips,
                MAX_TRACKED_IPS_CEILING
            );
        }
        // 64 GiB is a generous ceiling for the total cache — beyond
        // this you're shifting the bottleneck to host memory. Configure
        // explicitly with a justification.
        const MAX_MEDIA_CACHE_TOTAL_MB: u64 = 65_536;
        if self.ipfs.media_cache_total_mb > MAX_MEDIA_CACHE_TOTAL_MB {
            anyhow::bail!(
                "ipfs.media_cache_total_mb = {} exceeds the safety cap of {} MiB",
                self.ipfs.media_cache_total_mb,
                MAX_MEDIA_CACHE_TOTAL_MB
            );
        }
        // SOFT FIXES below — auto-clamp and emit a warning rather than
        // bailing. `eprintln` is used instead of `tracing::warn` because
        // validation runs BEFORE the tracing subscriber is initialized;
        // a tracing warn would be silently dropped.
        //
        // Per-item cap larger than max upload: items that large can't
        // enter the system in the first place, so the over-spec is
        // harmless. Clamp to keep the displayed config self-consistent.
        if self.ipfs.media_cache_item_mb > self.ipfs.max_upload_size_mb {
            eprintln!(
                "[config] ipfs.media_cache_item_mb ({}) > ipfs.max_upload_size_mb ({}); \
                 clamping to {} (items larger than max_upload can't enter the system).",
                self.ipfs.media_cache_item_mb,
                self.ipfs.max_upload_size_mb,
                self.ipfs.max_upload_size_mb,
            );
            self.ipfs.media_cache_item_mb = self.ipfs.max_upload_size_mb;
        }
        // Per-item cap larger than total cache: each cached item would
        // evict every other item. Clamp so the LRU has room to keep
        // SOMETHING after each insert.
        if self.ipfs.media_cache_item_mb > self.ipfs.media_cache_total_mb {
            eprintln!(
                "[config] ipfs.media_cache_item_mb ({}) > ipfs.media_cache_total_mb ({}); \
                 clamping to {} (cap per item must fit within total cache).",
                self.ipfs.media_cache_item_mb,
                self.ipfs.media_cache_total_mb,
                self.ipfs.media_cache_total_mb,
            );
            self.ipfs.media_cache_item_mb = self.ipfs.media_cache_total_mb;
        }
        // Trusted-proxy CIDRs (v0.42). Parse-validate each entry at
        // load time; HARD reject on first malformed entry. Silently
        // dropping a bad CIDR would flip the security model: an
        // operator who typo'd "10.0.0/8" expecting it to cover
        // "10.0.0.0/8" would have the immediate peer NOT trusted —
        // requests from their proxy would return the proxy IP, not
        // the real client, which the operator wouldn't notice until
        // their rate-limit metrics looked off.
        for (idx, entry) in self.api.trusted_proxies.iter().enumerate() {
            crate::trusted_proxies::TrustedProxy::parse(entry).with_context(|| {
                format!("api.trusted_proxies[{}] = {:?}", idx, entry)
            })?;
        }
        Ok(())
    }

    /// Generate a default configuration file content.
    pub fn default_toml() -> String {
        r#"[node]
data_dir = "./data"

[network]
listen_port = 41720
# Bootstrap peer multiaddrs (spec 13 §4.2).
#
# Empty default → pure SC-driven discovery: the node queries
# getActiveNodes + getNodeMetadata on the Ogmara KApp to find peers.
# Populate with explicit peer multiaddrs (including /p2p/<peer_id>) to
# either supplement SC discovery (hybrid mode, sc_discovery.enabled =
# true) or replace it entirely (isolated subnet, sc_discovery.enabled
# = false). See [network.sc_discovery] below.
bootstrap_nodes = []
max_peers = 50
enable_mdns = true
# Network isolation: auto-detected from klever.node_url if not set.
# Valid values: "testnet", "mainnet".
# network_id = "testnet"

[network.discovery]
# Drop dial-candidate peers whose on-chain `lastAnchorAt` is older than
# this many days (spec 13 §7). Tier 3 (SC registry) entries only; tier
# 1 (peer book) and tier 2 (config bootstrap) carry no anchor timestamp.
# Default 7. Local-only dev deployments may want a longer threshold;
# production nodes should stick with the default.
max_peer_staleness_days = 7

[network.tor]
# Onion-transport surface — external Tor daemon + SOCKS5 wrapper
# (spec 13 §6.4, l2-node 0.46.9+). Disabled by default; operators
# with regulatory-resilience requirements opt in.
#
# When enabled = true, the operator MUST already run a Tor daemon
# (apt install tor / brew install tor / etc.). The L2 node uses the
# daemon's local SOCKS proxy for outbound onion dials (deferred to a
# future release) and accepts inbound connections forwarded by the
# daemon's hidden-service definition for the loopback port below.
enabled = false
# Local Tor SOCKS5 proxy. Must be a loopback host (validator refuses
# non-loopback to prevent operators from unwittingly routing onion
# traffic through a remote SOCKS server).
socks_proxy = "127.0.0.1:9050"
# Loopback TCP port the swarm listens on when an onion hostname is
# configured. The torrc HiddenServicePort directive forwards
# `<onion_virtual_port>` to `127.0.0.1:<listen_onion_port>`. Zero
# disables inbound onion listen.
listen_onion_port = 0
# .onion hostname from /var/lib/tor/<hs_dir>/hostname. Must be a v3
# onion (56 base32 chars + ".onion"). Empty disables inbound onion
# listen and metadata advertisement.
listen_onion_hostname = ""
# When true, the metadata reconciler appends the onion multiaddr to
# the desired list it compares against on-chain getNodeMetadata(self).
# Operator still has to click Publish in the dashboard to broadcast
# (spec 12 §6.2 no-proxy-signing rule).
advertise_onion_in_metadata = false

[network.sc_discovery]
# SC-driven bootstrap control surface (spec 13 §4.2, l2-node 0.46.5+).
# `enabled = true` (default) keeps the node discovering peers from the
# on-chain registry. Set `enabled = false` together with an explicit
# `bootstrap_nodes` list to run an isolated subnet that never queries
# Klever for peer discovery (useful where Klever endpoints are
# geo-blocked or surveilled). The both-empty case is rejected at
# config-load.
enabled = true
# Cold-start retry cadence (seconds). When bootstrap_nodes is empty
# and the peer book is empty, the discovery task retries on this
# cadence until at least one peer is persisted. Once warm, it falls
# back to the steady-state 1-hour periodic refresh.
retry_interval_secs = 60
# Maximum peers to dial per cold-start fan-out. The fan-out still
# PERSISTS up to 256 peers (matches PEER_DIRECTORY cap); this knob
# caps the immediate dial set so a fresh node doesn't burst-connect.
max_candidates = 5

[network.presence]
# Off-chain presence-gossip subsystem (spec 13 §10, l2-node 0.48.0+).
#
# When `enabled = true` AND [api] public_url is non-empty, the node
# broadcasts a signed PresenceRecord on the
# /ogmara/{network_id}/presence/v1 gossipsub topic so other nodes and
# the public Network page can list this node as a service provider
# WITHOUT on-chain registration. Independent of [anchoring] —
# operators may participate in presence gossip alone, in SC anchoring
# alone, or in both (the recommended production configuration for
# anchoring operators).
#
# Default off — participation is explicit, mirroring [anchoring].
enabled = false
# How long our records stay valid in peers' caches (and the cap on
# how stale our cached records of OTHER nodes can be before we drop
# them). Default 24h; max 7 days (604_800). Validated at startup.
record_ttl_secs = 86400
# How often we re-sign and re-broadcast our own record. Must be
# strictly less than record_ttl_secs / 2 so peers always have a valid
# record between re-broadcasts. Validated at startup — invalid values
# abort with a config-fix message. v0.48.2: default lowered from
# 21600 (6h) to 3600 (1h) so caches converge in a realistic
# operator-debug window on small testnets.
rebroadcast_interval_secs = 3600
# Peers whose presence records we never accept (libp2p PeerIds).
# Useful for surgical exclusion of known-bad operators without
# touching the SC denylist. Empty default. Each entry must parse as a
# base58-encoded libp2p PeerId (e.g. "12D3KooW..."); malformed entries
# abort startup.
denylist = []

[klever]
node_url = ""
api_url = ""
contract_address = ""
scan_interval_ms = 3000
# Skip blocks before SC deployment (saves hours on first sync).
# Only used when chain cursor is 0 (fresh node). Ignored once scanning has started.
# Mainnet: 29686185, Testnet: 9100000
start_block = 0

[ipfs]
api_url = "http://127.0.0.1:5001"
gateway_url = "http://127.0.0.1:8080"
max_upload_size_mb = 50
auto_thumbnail = true
# Media handler tuning (v0.39+). All optional with sensible defaults
# for a ~4 GiB-RAM VPS. Lower for resource-constrained nodes; raise
# for high-readership deployments. See IpfsConfig field docs for the
# safety constraints (validated at config-load).
media_cache_total_mb = 256        # Total LRU weight cap
media_cache_item_mb = 16          # Per-item insert cap; larger items stream
media_handler_permits = 32        # Concurrent /api/v1/media/:cid handlers (global)
media_per_ip_permits = 4          # Per-client-IP sub-cap (must be <= handler_permits)
media_max_tracked_ips = 65536     # Hard cap on the per-IP limiter map

[media]
# Cross-node media-fetch fallback (spec 3, l2-node 0.46.7+).
#
# When a media request misses the local Kubo, the node optionally
# fans out to SC-registered peers (from getActiveNodes filtered by
# anchor recency) and races their /api/v1/media/:cid responses.
# Trust set is strict at launch: only on-chain-registered, anchoring,
# unpaused peers. The retrieved content is re-added to the local
# Kubo, content-verified against the requested CID, and pinned for
# future requests.
#
# Set peer_fallback_enabled = false for strictly-local serving
# (privacy-conscious archive nodes that should not generate outbound
# HTTP requests to peers).
peer_fallback_enabled = true
peer_fallback_fanout = 3                 # parallel dials per fetch (cap 16)
peer_fallback_connect_timeout_secs = 5   # connect timeout per dial
peer_fallback_read_timeout_secs = 30     # end-to-end read budget per dial
peer_fallback_global_concurrent = 16     # global concurrent fan-out ops (cap 256)
peer_fallback_candidate_cache_secs = 300 # SC candidate snapshot TTL

[backfill]
# Channel-history reconciliation (spec 1, l2-node 0.47.0+).
#
# On the first subscribe to a channel where the local index is empty
# (cold-join), the node requests missing history from peers and
# applies it through the standard message router (signature verify,
# storage admission, the works). Default on so fresh nodes catch up
# automatically; set enabled = false for bandwidth-constrained
# deployments that want users to rely on real-time gossip only.
enabled = true
# How far back to fetch. Archive operators set u64::MAX (currently
# 18446744073709551615) for "everything ever stored by the peer".
max_age_days = 30
# Client-side concurrent peer dials. First peer with a non-empty
# response wins; the others are dropped.
fanout = 3
# Server-side caps — refuse to drown a single requester (per peer
# and per channel) but always respond promptly with server_capped =
# true so they know to back off.
server_max_concurrent_per_peer = 4
server_max_concurrent_per_channel = 1
# Per-response envelope cap. Total bandwidth is the SAME as a
# bigger cap — clients page via the cursor — but smaller batches
# cut worst-case latency.
max_envelopes_per_response = 1000
# Hard ceiling on total envelopes served per single client stream.
# 200k = roughly one year of an active channel; stops a malicious
# client from inducing an unbounded scan.
total_envelopes_cap = 200000
# Re-reconciliation knob. 0 = off (gossip mesh fills gaps in real
# time). N>0 = re-trigger on subscribe if local history's newest
# envelope is older than N days. Bandwidth cost; default off.
force_resync_if_stale_days = 0

[api]
# Set to "0.0.0.0" to accept connections from all interfaces
listen_addr = "127.0.0.1"
listen_port = 41721
# Public URL where this node's API is reachable from the public internet
# (e.g. "https://node.example.org"). REQUIRED for:
#   - inclusion in `/api/v1/network/nodes` advertising
#   - [anchoring.metadata] auto-derive (spec 13 §6.1) to compute the
#     /dns4|/ip4|/ip6 multiaddr the SC publishes on chain
# v0.46.0 Phase D supports bracketed IPv6 (`http://[2001:db8::1]:41721`).
# public_url = "https://node.example.org"
# Includes `https://ogmara.org` so the public network page's
# browser-side reachability probe can reach a fresh node without
# extra config. Remove it if you want a narrower origin policy.
cors_origins = ["https://ogmara.org", "http://localhost:*"]
rate_limit_per_ip = 100
# Trusted-proxy CIDRs for client-IP resolution behind a reverse proxy
# (v0.42). Each entry is a CIDR (`"10.0.0.0/8"`, `"2001:db8::/32"`) or
# a bare address (`"192.0.2.5"`, `"::1"`). Loopback is always implicitly
# trusted. Leave empty for single-host deployments where Apache/nginx
# sits on loopback in front of the node. Malformed entries abort startup.
# trusted_proxies = []

[api.pow]
enabled = true
difficulty = 20
challenge_ttl_seconds = 300

[api.admin]
enabled = true
dashboard = true
admin_wallets = []
session_ttl_hours = 24

[storage]
engine = "rocksdb"
max_db_size_gb = 50
pinned_channels = []

[cache]
ttl_seconds = 86400
max_size_mb = 1024
auto_pin_on_interaction = true

[push_gateway]
enabled = false
url = ""
auth_token = ""

[anchoring]
enabled = false
interval_seconds = 3600
# wallet_key = ""  # optional, defaults to node identity key. Prefer
# the OGMARA_ANCHOR_WALLET_KEY env var over putting the key in the
# config file. v0.46.0 wraps this field in `secrecy::SecretString` so
# the source is zeroized on drop and redacted in logs.
# pause_on_shutdown = false  # spec 13 §6.3: if true, SIGTERM signs +
# broadcasts pauseNode before exit. Requires wallet_key set. Opt-in
# because it broadens the wallet-key threat surface (key held in
# process memory for shutdown signing, not just during the anchor loop).

[anchoring.metadata]
# On-chain peer-discovery publication (spec 12 §2.10, spec 13 §6.1).
# Opt-in — non-publishers still anchor and count toward quorum but
# do not appear in `getActiveNodes` discovery output. This is the
# first-class privacy mode per spec 13 §6.2.
publish = false
# When `publish = true` AND this list is empty, the node auto-derives
# from [api] public_url + [network] listen_port:
#   /dns4/<hostname>/tcp/<port>/p2p/<peer_id> + QUIC variant for DNS
#   /ip4/<addr>/...                              for IPv4 literals
#   /ip6/<addr>/...                              for routable IPv6 literals
# Operators with non-trivial topology (NAT, load-balancer, anonymizer,
# onion) set this explicitly. Cap: 8 entries × 256 bytes each (SC limit).
multiaddrs = []

[snapshot]
# Peer-to-peer state snapshots (spec 11-snapshot-sync.md).
# Phase 3 (v0.36): default-on. Fresh nodes fetch the snapshot from
# peers and re-verify every anchor against Klever before applying.
serve_enabled = true
serve_rebuild_interval_secs = 3600
chunk_size_bytes = 4194304            # 4 MiB
serve_max_concurrent_requests = 8

# Bootstrap client — default-on in v0.36. Fresh nodes auto-bootstrap
# from peers if a quorum agrees on a snapshot AND every anchor up to
# cutoff_height verifies against Klever's getStateRoot view function.
bootstrap_enabled = true
bootstrap_only_if_fresh = true           # Refuse to overwrite an existing node's state
allow_apply_over_existing = false        # Force operator override to apply over data

quorum_sample_size = 5
# Minimum agreeing peers required for the bootstrap quorum. The default
# of 3 is production-safe (no single peer can foist a poisoned snapshot
# on a new node). On a SMALL / PRIVATE NETWORK — local dev box pair,
# 2-node testnet, single-tenant rollout — bootstrap will silently never
# run because fewer than 3 peers exist to even probe. Lower to 1 or 2
# for those setups; understand that you're trading the quorum vote for
# trust in your immediate peer. The anchor re-verification against
# Klever still applies regardless, so a single dishonest peer can't
# trick you into accepting state that doesn't match the chain.
quorum_min_peers = 3
parallel_fetches = 3
chunk_retries = 5
discovery_timeout_secs = 30
manifest_timeout_secs = 10
chunk_timeout_secs = 60
max_total_bytes = 2147483648             # 2 GiB hard cap on snapshot size

# DANGEROUS — TESTNET / SMALL-NETWORK ONLY. Skip the Klever
# `getStateRoot` re-verification of every anchor in the received
# snapshot. The SC requires ANCHOR_QUORUM_MIN=3 distinct anchorers
# to agree on a state root before promoting it to canonical, so
# `getStateRoot` returns "Anchor not found" on networks with fewer
# than 3 active anchorers. Setting this true short-circuits the
# anchor loop while still requiring quorum + Merkle + producer
# signature. Leave false in production. A loud warning is logged
# at startup whenever this is true.
experimental_skip_anchor_verify = false

[metrics]
enabled = true
system_interval_seconds = 10
ipfs_interval_seconds = 30
storage_interval_seconds = 60
history_capacity = 1440

[alerts]
enabled = false

[alerts.cooldown]
seconds = 300

[alerts.thresholds]
min_peers = 3
max_disk_usage_percent = 90
max_memory_usage_percent = 85
# Anchor divergence: fire `anchor_divergence` (critical) when this many
# consecutive canonicalized heights show our local root differing from
# the on-chain canonical root (spec 12 §6.1, spec 10 §9.2). Default: 2.
anchor_divergence_consecutive = 2

# --- Alert dispatcher backends (spec 10 §9.4) -------------------------
# Each backend is independent; enable any subset. Secrets (bot_token,
# webhook_url) should be loaded from environment variables in production
# rather than written to the config file. The shipping pattern: leave
# `enabled = false` here, set the secret env var, then flip enabled to
# `true` in a deployment overlay or before container start.

[alerts.telegram]
enabled = false
# chat_id = "-100123456789"
# bot_token loaded from $TELEGRAM_BOT_TOKEN env var (preferred) —
# avoid putting the token in this file.

[alerts.discord]
enabled = false
# webhook_url loaded from $DISCORD_WEBHOOK_URL env var (preferred) —
# avoid putting the URL in this file (it grants post-as-channel rights).

[alerts.webhook]
enabled = false
# url = "https://example.org/ogmara-alert"

[logging]
level = "info"
format = "json"
"#
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a baseline `Config` for validation tests by parsing the
    /// canonical `default_toml()`. Each test mutates the fields it
    /// cares about, then calls `validate()`.
    fn baseline_config() -> Config {
        toml::from_str(&Config::default_toml()).expect("default toml parses")
    }

    // --- Hard rejects ---------------------------------------------------

    #[test]
    fn validate_rejects_zero_media_permits() {
        let mut c = baseline_config();
        c.ipfs.media_handler_permits = 0;
        let err = c.validate().expect_err("zero permits must reject");
        assert!(format!("{}", err).contains("media_handler_permits"));
    }

    #[test]
    fn validate_rejects_zero_media_cache_total() {
        let mut c = baseline_config();
        c.ipfs.media_cache_total_mb = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_media_cache_item() {
        let mut c = baseline_config();
        c.ipfs.media_cache_item_mb = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_oversized_media_cache_total() {
        let mut c = baseline_config();
        c.ipfs.media_cache_total_mb = 1_000_000; // 1 TiB — way over cap
        let err = c.validate().expect_err("oversized total must reject");
        assert!(format!("{}", err).contains("media_cache_total_mb"));
    }

    #[test]
    fn validate_rejects_oversized_permits() {
        let mut c = baseline_config();
        c.ipfs.media_handler_permits = 100_000;
        assert!(c.validate().is_err());
    }

    // --- Soft fixes (v0.40.1 regression) --------------------------------

    /// Regression: pre-0.40.1 this combination (default item_mb=16
    /// against a smaller-than-default max_upload_mb=10) caused the
    /// process to exit at startup. The fix clamps + warns instead of
    /// bailing — production nodes with pre-v0.40 configs upgrade
    /// without operator intervention.
    #[test]
    fn validate_clamps_item_to_max_upload_instead_of_failing() {
        let mut c = baseline_config();
        c.ipfs.max_upload_size_mb = 10;
        c.ipfs.media_cache_item_mb = 16; // would have been the v0.40.0 default
        c.validate().expect("must NOT bail on this combination");
        assert_eq!(
            c.ipfs.media_cache_item_mb, 10,
            "item_mb should be clamped to max_upload_mb",
        );
    }

    #[test]
    fn validate_clamps_item_to_total_when_misconfigured() {
        let mut c = baseline_config();
        c.ipfs.media_cache_total_mb = 8;
        c.ipfs.media_cache_item_mb = 100;
        c.ipfs.max_upload_size_mb = 200; // not the bottleneck this time
        c.validate().expect("must NOT bail; clamp instead");
        assert!(
            c.ipfs.media_cache_item_mb <= 8,
            "item_mb clamped via max_upload then total: got {}",
            c.ipfs.media_cache_item_mb
        );
    }

    #[test]
    fn validate_passes_defaults_unchanged() {
        // Sanity: the canonical default config from `default_toml()`
        // must pass validation without any clamping. Catches a future
        // bump to a default value that conflicts with the validation.
        let mut c = baseline_config();
        let before = c.ipfs.media_cache_item_mb;
        c.validate().expect("defaults must pass");
        assert_eq!(c.ipfs.media_cache_item_mb, before, "no clamping on defaults");
    }

    #[test]
    fn validate_passes_when_item_equals_max_upload() {
        // Boundary case — equality is allowed.
        let mut c = baseline_config();
        c.ipfs.max_upload_size_mb = 16;
        c.ipfs.media_cache_item_mb = 16;
        c.validate().expect("equality is fine");
        assert_eq!(c.ipfs.media_cache_item_mb, 16);
    }

    // --- 0.46.5 SC-driven bootstrap (spec 13 §4.2) -------------------

    #[test]
    fn validate_rejects_empty_bootstrap_and_disabled_sc() {
        // Both-empty case: no way to discover peers.
        let mut c = baseline_config();
        c.network.bootstrap_nodes.clear();
        c.network.sc_discovery.enabled = false;
        let err = c
            .validate()
            .expect_err("both-empty must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("bootstrap_nodes"), "error should mention bootstrap_nodes: {msg}");
        assert!(msg.contains("sc_discovery"), "error should mention sc_discovery: {msg}");
    }

    #[test]
    fn validate_accepts_empty_bootstrap_with_sc_enabled() {
        // Pure SC mode — the new default. Must pass.
        let mut c = baseline_config();
        c.network.bootstrap_nodes.clear();
        c.network.sc_discovery.enabled = true;
        c.validate().expect("pure SC mode must validate");
    }

    #[test]
    fn validate_accepts_explicit_peers_with_sc_disabled() {
        // Isolated subnet mode — explicit peers + SC disabled. Must pass.
        let mut c = baseline_config();
        c.network.bootstrap_nodes =
            vec!["/dns4/example.invalid/tcp/41720/p2p/12D3KooWNx9TnsmVQux3fMm6sUUe5tFdeXjECUSyDqYtYfsbt3Mo".to_string()];
        c.network.sc_discovery.enabled = false;
        c.validate().expect("isolated subnet mode must validate");
    }

    #[test]
    fn default_bootstrap_nodes_is_empty() {
        // Spec 13 §4.2: 0.46.5+ ships an empty default. The legacy
        // node.ogmara.org seed list MUST NOT be reintroduced via the
        // default helper.
        assert!(super::default_bootstrap_nodes().is_empty());
    }

    #[test]
    fn validate_rejects_zero_sc_retry_interval() {
        // Security Audit W2: 0 would hot-spin the SC RPC.
        let mut c = baseline_config();
        c.network.sc_discovery.retry_interval_secs = 0;
        let err = c.validate().expect_err("0 retry must be rejected");
        assert!(format!("{err}").contains("retry_interval_secs"));
    }

    #[test]
    fn validate_rejects_below_floor_sc_retry_interval() {
        // 1, 2, 3, 4 are all below the 5-second floor.
        for v in 1..=4 {
            let mut c = baseline_config();
            c.network.sc_discovery.retry_interval_secs = v;
            assert!(
                c.validate().is_err(),
                "retry_interval_secs = {v} must be rejected",
            );
        }
    }

    #[test]
    fn validate_accepts_floor_sc_retry_interval() {
        let mut c = baseline_config();
        c.network.sc_discovery.retry_interval_secs = 5;
        c.validate().expect("floor value must pass");
    }

    #[test]
    fn validate_rejects_zero_max_candidates() {
        // Code Audit W2: silently clamping operator misconfig is
        // worse than failing loudly at config-load.
        let mut c = baseline_config();
        c.network.sc_discovery.max_candidates = 0;
        let err = c.validate().expect_err("0 max_candidates must be rejected");
        assert!(format!("{err}").contains("max_candidates"));
    }

    // --- 0.46.7 media peer-fallback (spec 3) -------------------------

    #[test]
    fn validate_passes_disabled_media_fallback_with_zeros() {
        // When peer_fallback_enabled = false, zero-valued tunables are
        // ignored (the path is unused). Don't make operators set
        // bookkeeping values they will never exercise.
        let mut c = baseline_config();
        c.media.peer_fallback_enabled = false;
        c.media.peer_fallback_fanout = 0;
        c.media.peer_fallback_connect_timeout_secs = 0;
        c.media.peer_fallback_read_timeout_secs = 0;
        c.media.peer_fallback_global_concurrent = 0;
        c.media.peer_fallback_candidate_cache_secs = 0;
        c.validate().expect("zero values are fine when disabled");
    }

    #[test]
    fn validate_rejects_zero_media_fanout_when_enabled() {
        let mut c = baseline_config();
        c.media.peer_fallback_enabled = true;
        c.media.peer_fallback_fanout = 0;
        let err = c.validate().expect_err("0 fanout must be rejected when enabled");
        assert!(format!("{err}").contains("peer_fallback_fanout"));
    }

    #[test]
    fn validate_rejects_oversized_media_fanout() {
        let mut c = baseline_config();
        c.media.peer_fallback_fanout = 17;
        let err = c.validate().expect_err("oversize fanout must be rejected");
        assert!(format!("{err}").contains("peer_fallback_fanout"));
    }

    #[test]
    fn validate_rejects_zero_media_timeouts() {
        let mut c = baseline_config();
        c.media.peer_fallback_connect_timeout_secs = 0;
        assert!(c.validate().is_err(), "0 connect timeout must be rejected");

        let mut c = baseline_config();
        c.media.peer_fallback_read_timeout_secs = 0;
        assert!(c.validate().is_err(), "0 read timeout must be rejected");
    }

    #[test]
    fn validate_rejects_zero_media_candidate_cache() {
        // 0 cache would hammer the SC RPC on every fallback fetch.
        let mut c = baseline_config();
        c.media.peer_fallback_candidate_cache_secs = 0;
        let err = c
            .validate()
            .expect_err("0 candidate cache TTL must be rejected when enabled");
        assert!(format!("{err}").contains("peer_fallback_candidate_cache_secs"));
    }

    #[test]
    fn validate_rejects_oversized_media_global_concurrent() {
        let mut c = baseline_config();
        c.media.peer_fallback_global_concurrent = 257;
        let err = c
            .validate()
            .expect_err("oversize global concurrent cap must be rejected");
        assert!(format!("{err}").contains("peer_fallback_global_concurrent"));
    }

    // --- 0.46.9 Tor / onion transport (spec 13 §6.4) -----------------

    #[test]
    fn validate_passes_disabled_tor_with_any_values() {
        // When `enabled = false`, none of the Tor knobs are checked.
        // Operators can leave a stale config that referenced
        // network.tor in place without the validator complaining.
        let mut c = baseline_config();
        c.network.tor.enabled = false;
        c.network.tor.socks_proxy = "not even a valid address".to_string();
        c.network.tor.listen_onion_hostname = "garbage".to_string();
        c.network.tor.listen_onion_port = 0;
        c.network.tor.advertise_onion_in_metadata = true;
        c.validate().expect("disabled tor skips field-level checks");
    }

    #[test]
    fn validate_rejects_non_loopback_socks_proxy() {
        let mut c = baseline_config();
        c.network.tor.enabled = true;
        c.network.tor.socks_proxy = "8.8.8.8:9050".to_string();
        let err = c
            .validate()
            .expect_err("non-loopback SOCKS proxy must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("loopback"), "error must mention loopback: {msg}");
    }

    #[test]
    fn validate_rejects_malformed_socks_proxy() {
        let mut c = baseline_config();
        c.network.tor.enabled = true;
        c.network.tor.socks_proxy = "not-a-socket".to_string();
        let err = c.validate().expect_err("malformed socks_proxy must reject");
        assert!(format!("{err}").contains("socks_proxy"));
    }

    #[test]
    fn validate_rejects_short_onion_hostname() {
        let mut c = baseline_config();
        c.network.tor.enabled = true;
        c.network.tor.listen_onion_hostname = "tooshort.onion".to_string();
        c.network.tor.listen_onion_port = 41720;
        let err = c
            .validate()
            .expect_err("non-v3 hostname must be rejected");
        assert!(format!("{err}").contains("v3 onion"));
    }

    #[test]
    fn validate_rejects_v3_onion_with_zero_port() {
        let mut c = baseline_config();
        c.network.tor.enabled = true;
        c.network.tor.listen_onion_hostname =
            format!("{}.onion", "a".repeat(56));
        c.network.tor.listen_onion_port = 0;
        let err = c
            .validate()
            .expect_err("zero port with hostname set must be rejected");
        assert!(format!("{err}").contains("listen_onion_port"));
    }

    #[test]
    fn validate_rejects_advertise_without_hostname() {
        let mut c = baseline_config();
        c.network.tor.enabled = true;
        c.network.tor.advertise_onion_in_metadata = true;
        c.network.tor.listen_onion_hostname = String::new();
        c.network.tor.listen_onion_port = 41720;
        let err = c
            .validate()
            .expect_err("advertise without hostname must be rejected");
        assert!(format!("{err}").contains("advertise_onion_in_metadata"));
    }

    #[test]
    fn validate_accepts_v3_onion_hostname() {
        // 56 lowercase-base32 chars + ".onion".
        let mut c = baseline_config();
        c.network.tor.enabled = true;
        c.network.tor.listen_onion_hostname =
            format!("{}.onion", "a".repeat(56));
        c.network.tor.listen_onion_port = 41720;
        c.validate().expect("valid v3 onion config must pass");
    }

    #[test]
    fn validate_rejects_non_ascii_onion_hostname() {
        let mut c = baseline_config();
        c.network.tor.enabled = true;
        c.network.tor.listen_onion_hostname = "ünicode.onion".to_string();
        c.network.tor.listen_onion_port = 41720;
        let err = c.validate().expect_err("non-ASCII onion must be rejected");
        assert!(format!("{err}").contains("ASCII"));
    }

    #[test]
    fn validate_passes_outbound_only_tor() {
        // Tor enabled but no inbound listen — outbound-only mode.
        let mut c = baseline_config();
        c.network.tor.enabled = true;
        c.network.tor.socks_proxy = "127.0.0.1:9050".to_string();
        c.network.tor.listen_onion_hostname = String::new();
        c.network.tor.listen_onion_port = 0;
        c.network.tor.advertise_onion_in_metadata = false;
        c.validate().expect("outbound-only tor must pass");
    }

    // --- 0.47.0 channel-history backfill (spec 1) -------------------

    #[test]
    fn validate_passes_disabled_backfill_with_zeros() {
        let mut c = baseline_config();
        c.backfill.enabled = false;
        c.backfill.fanout = 0;
        c.backfill.server_max_concurrent_per_peer = 0;
        c.backfill.server_max_concurrent_per_channel = 0;
        c.backfill.max_envelopes_per_response = 0;
        c.backfill.total_envelopes_cap = 0;
        c.backfill.max_age_days = 0;
        c.validate().expect("disabled backfill skips field checks");
    }

    #[test]
    fn validate_rejects_zero_backfill_fanout() {
        let mut c = baseline_config();
        c.backfill.fanout = 0;
        let err = c.validate().expect_err("0 fanout must be rejected");
        assert!(format!("{err}").contains("backfill.fanout"));
    }

    #[test]
    fn validate_rejects_oversized_backfill_fanout() {
        let mut c = baseline_config();
        c.backfill.fanout = 17;
        let err = c.validate().expect_err("oversize fanout must be rejected");
        assert!(format!("{err}").contains("backfill.fanout"));
    }

    #[test]
    fn validate_rejects_zero_backfill_server_caps() {
        let mut c = baseline_config();
        c.backfill.server_max_concurrent_per_peer = 0;
        assert!(c.validate().is_err());

        let mut c = baseline_config();
        c.backfill.server_max_concurrent_per_channel = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_backfill_envelopes_per_response() {
        let mut c = baseline_config();
        c.backfill.max_envelopes_per_response = 0;
        let err = c.validate().expect_err("0 envelopes/response must reject");
        assert!(format!("{err}").contains("max_envelopes_per_response"));
    }

    #[test]
    fn validate_rejects_oversized_backfill_envelopes_per_response() {
        let mut c = baseline_config();
        c.backfill.max_envelopes_per_response = 50_001;
        let err = c
            .validate()
            .expect_err("oversize envelopes/response must reject");
        assert!(format!("{err}").contains("max_envelopes_per_response"));
    }

    #[test]
    fn validate_rejects_zero_backfill_max_age_days() {
        let mut c = baseline_config();
        c.backfill.max_age_days = 0;
        let err = c
            .validate()
            .expect_err("0 max_age_days must reject when enabled");
        assert!(format!("{err}").contains("max_age_days"));
    }

    #[test]
    fn validate_accepts_archive_backfill_unlimited_age() {
        let mut c = baseline_config();
        c.backfill.max_age_days = u64::MAX;
        c.validate().expect("u64::MAX archive mode must pass");
    }

    // --- v0.41 per-IP permit field ----------------------------------

    #[test]
    fn validate_rejects_zero_per_ip_permits() {
        let mut c = baseline_config();
        c.ipfs.media_per_ip_permits = 0;
        let err = c.validate().expect_err("zero per-IP permits must reject");
        assert!(format!("{}", err).contains("media_per_ip_permits"));
    }

    #[test]
    fn validate_clamps_per_ip_to_global_permits() {
        // Operator typo / pre-v0.41 config that explicitly set
        // per_ip = 1000. The auto-clamp lets the node still boot
        // while quietly pulling per_ip back to the global cap.
        let mut c = baseline_config();
        c.ipfs.media_handler_permits = 32;
        c.ipfs.media_per_ip_permits = 1000;
        c.validate().expect("must clamp, not bail");
        assert_eq!(c.ipfs.media_per_ip_permits, 32);
    }

    #[test]
    fn validate_passes_default_per_ip_permits() {
        // Default per-IP (4) is well below default global (32).
        let mut c = baseline_config();
        c.validate().expect("defaults pass");
        assert_eq!(c.ipfs.media_per_ip_permits, 4);
    }

    // --- v0.42 max_tracked_ips field --------------------------------

    #[test]
    fn validate_rejects_zero_max_tracked_ips() {
        let mut c = baseline_config();
        c.ipfs.media_max_tracked_ips = 0;
        let err = c.validate().expect_err("zero must reject");
        assert!(format!("{}", err).contains("media_max_tracked_ips"));
    }

    #[test]
    fn validate_rejects_oversized_max_tracked_ips() {
        let mut c = baseline_config();
        c.ipfs.media_max_tracked_ips = 100_000_000; // way over ceiling
        let err = c.validate().expect_err("oversized must reject");
        assert!(format!("{}", err).contains("media_max_tracked_ips"));
    }

    #[test]
    fn validate_passes_default_max_tracked_ips() {
        let mut c = baseline_config();
        c.validate().expect("defaults pass");
        assert_eq!(c.ipfs.media_max_tracked_ips, 65_536);
    }

    // --- v0.42 trusted_proxies field --------------------------------

    #[test]
    fn validate_accepts_empty_trusted_proxies() {
        let mut c = baseline_config();
        assert!(c.api.trusted_proxies.is_empty());
        c.validate().expect("empty list (= loopback-only) is fine");
    }

    #[test]
    fn validate_accepts_well_formed_trusted_proxies() {
        let mut c = baseline_config();
        c.api.trusted_proxies = vec![
            "10.0.0.0/8".to_string(),
            "192.168.1.5".to_string(),
            "2001:db8::/32".to_string(),
            "::1".to_string(),
        ];
        c.validate().expect("all entries parse");
    }

    #[test]
    fn validate_rejects_malformed_trusted_proxy() {
        let mut c = baseline_config();
        c.api.trusted_proxies = vec![
            "10.0.0.0/8".to_string(),
            "not-an-ip".to_string(),
        ];
        let err = c.validate().expect_err("garbage entry must reject");
        assert!(format!("{:?}", err).contains("trusted_proxies"));
    }

    #[test]
    fn validate_rejects_oversized_prefix() {
        let mut c = baseline_config();
        c.api.trusted_proxies = vec!["1.2.3.4/33".to_string()];
        assert!(c.validate().is_err());
    }

    // --- AnchoringConfig.wallet_key SecretString round-trip (v0.46.0 Phase C) ---

    #[test]
    fn wallet_key_default_is_none() {
        let cfg = AnchoringConfig::default();
        assert!(cfg.wallet_key.is_none());
        assert_eq!(cfg.wallet_key_hex(), None);
    }

    #[test]
    fn wallet_key_absent_in_toml_is_none() {
        let toml = "enabled = false\ninterval_seconds = 3600\n";
        let cfg: AnchoringConfig = toml::from_str(toml).expect("parses");
        assert!(cfg.wallet_key.is_none());
    }

    #[test]
    fn wallet_key_empty_string_in_toml_is_none() {
        // Pre-0.46.0 contract: explicit `wallet_key = ""` meant "absent".
        // The custom deserializer must preserve that for backwards compat.
        let toml = "enabled = false\ninterval_seconds = 3600\nwallet_key = \"\"\n";
        let cfg: AnchoringConfig = toml::from_str(toml).expect("parses");
        assert!(cfg.wallet_key.is_none());
        assert_eq!(cfg.wallet_key_hex(), None);
    }

    #[test]
    fn wallet_key_non_empty_string_wraps_in_secret() {
        let hex = "deadbeef".repeat(8); // 64 hex chars = 32 bytes
        let toml = format!(
            "enabled = true\ninterval_seconds = 3600\nwallet_key = \"{}\"\n",
            hex
        );
        let cfg: AnchoringConfig = toml::from_str(&toml).expect("parses");
        assert!(cfg.wallet_key.is_some());
        // expose_secret round-trips the exact string the operator put in.
        assert_eq!(cfg.wallet_key_hex(), Some(hex.as_str()));
    }

    #[test]
    fn wallet_key_debug_redacts_when_configured() {
        let hex = "ab".repeat(32);
        let toml = format!(
            "enabled = true\ninterval_seconds = 3600\nwallet_key = \"{}\"\n",
            hex
        );
        let cfg: AnchoringConfig = toml::from_str(&toml).expect("parses");
        let rendered = format!("{:?}", cfg);
        // Must NOT contain the hex string itself.
        assert!(
            !rendered.contains(&hex),
            "Debug rendering must not leak wallet_key; got: {}",
            rendered
        );
        // Must report the configured-vs-absent state.
        assert!(rendered.contains("\"<configured>\""));
    }

    #[test]
    fn wallet_key_debug_shows_none_when_absent() {
        let cfg = AnchoringConfig::default();
        let rendered = format!("{:?}", cfg);
        assert!(rendered.contains("\"<none>\""));
    }

    #[test]
    fn wallet_key_rejects_non_string_toml() {
        // `String::deserialize` rejects non-string TOML values. Guards
        // against a future refactor that swaps `String` for a more
        // permissive type (e.g., serde_json::Value) that would silently
        // accept integers or booleans (Phase C Code Audit / Security
        // Audit N4).
        let toml = "enabled = false\ninterval_seconds = 3600\nwallet_key = 42\n";
        assert!(toml::from_str::<AnchoringConfig>(toml).is_err());

        let toml = "enabled = false\ninterval_seconds = 3600\nwallet_key = true\n";
        assert!(toml::from_str::<AnchoringConfig>(toml).is_err());
    }

    #[test]
    fn wallet_key_clone_preserves_secret() {
        // `SecretString` implements `Clone`; the cloned struct must
        // expose the same secret. Both copies zeroize independently on
        // drop (verified at runtime by Drop; the test just confirms
        // semantic equality).
        let hex = "1234567890abcdef".repeat(4);
        let toml = format!(
            "enabled = true\ninterval_seconds = 3600\nwallet_key = \"{}\"\n",
            hex
        );
        let cfg: AnchoringConfig = toml::from_str(&toml).expect("parses");
        let cloned = cfg.clone();
        assert_eq!(cfg.wallet_key_hex(), cloned.wallet_key_hex());
        assert_eq!(cloned.wallet_key_hex(), Some(hex.as_str()));
    }

    // --- Config discoverability (v0.46.1) ----------------------------------
    //
    // `default_toml()` is the operator-facing surface: `ogmara-node init`
    // writes it, the docker entrypoint auto-creates it, and `ogmara.example.toml`
    // is regenerated from it. The tests below guard the discoverability
    // contract — every operator-tunable section must be visible (commented
    // or set) in the default, and the static example file must stay in sync.

    #[test]
    fn default_toml_includes_all_operator_tunable_sections() {
        let s = Config::default_toml();
        for section in &[
            "[node]",
            "[network]",
            "[network.discovery]",
            "[klever]",
            "[ipfs]",
            "[api]",
            "[api.pow]",
            "[api.admin]",
            "[storage]",
            "[cache]",
            "[push_gateway]",
            "[anchoring]",
            "[anchoring.metadata]",
            "[snapshot]",
            "[metrics]",
            "[alerts]",
            "[alerts.cooldown]",
            "[alerts.thresholds]",
            "[alerts.telegram]",
            "[alerts.discord]",
            "[alerts.webhook]",
            "[logging]",
        ] {
            assert!(
                s.contains(section),
                "default_toml must include `{}` section — operators rely on \
                 `ogmara-node init` to expose every tunable surface",
                section
            );
        }
    }

    #[test]
    fn default_toml_documents_v046_knobs() {
        // Sentinel field names that must appear (commented or set) so
        // operators using `ogmara-node init` can discover the v0.45/v0.46
        // surface area. Missing means the section header is there but
        // a critical field inside isn't.
        let s = Config::default_toml();
        for needle in &[
            "max_peer_staleness_days",   // [network.discovery]
            "public_url",                // [api] — needed by auto-derive
            "trusted_proxies",           // [api] — reverse-proxy IP resolution
            "media_cache_total_mb",      // [ipfs]
            "media_per_ip_permits",      // [ipfs] — v0.41 DoS mitigation
            "pause_on_shutdown",         // [anchoring] — spec 13 §6.3
            "publish",                   // [anchoring.metadata]
        ] {
            assert!(
                s.contains(needle),
                "default_toml must mention `{}` (commented is fine) so \
                 operators can discover the knob",
                needle
            );
        }
    }

    #[test]
    fn ogmara_example_toml_matches_default_toml() {
        // The static `ogmara.example.toml` shipped in the repo and the
        // docker image MUST stay in sync with `default_toml()` (the
        // single source of truth used by `ogmara-node init` and the
        // docker entrypoint). When this test fails after changing
        // `default_toml()`, regenerate the example file:
        //   cargo run --release -- init -o ogmara.example.toml
        let example = include_str!("../ogmara.example.toml");
        let generated = Config::default_toml();
        assert_eq!(
            example, generated,
            "ogmara.example.toml is out of sync with `Config::default_toml()`. \
             Regenerate: `cargo run --release -- init -o ogmara.example.toml`"
        );
    }
}
