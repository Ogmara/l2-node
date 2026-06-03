//! Composed libp2p NetworkBehaviour for the Ogmara node.
//!
//! Combines GossipSub, Kademlia, mDNS, Identify, and Request-Response
//! into a single behaviour for the swarm.

use std::time::Duration;

use anyhow::{Context, Result};
use libp2p::gossipsub::{self, MessageAuthenticity};
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{kad, Swarm, SwarmBuilder};

use crate::config::Config;

use super::reconcile::ReconcileCodec;
use super::snapshot::SnapshotCodec;
use super::sync::SyncCodec;

/// The composed network behaviour for the Ogmara node.
#[derive(NetworkBehaviour)]
pub struct OgmaraBehaviour {
    /// Connection limits to prevent resource exhaustion.
    pub connection_limits: libp2p::connection_limits::Behaviour,
    /// GossipSub for pub/sub message propagation.
    pub gossipsub: gossipsub::Behaviour,
    /// Kademlia DHT for peer discovery and content routing.
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// mDNS for local network peer discovery.
    pub mdns: libp2p::mdns::tokio::Behaviour,
    /// Identify for exchanging peer information.
    pub identify: libp2p::identify::Behaviour,
    /// Request-Response for sync protocol.
    pub request_response: libp2p::request_response::cbor::Behaviour<
        super::sync::SyncRequest,
        super::sync::SyncResponse,
    >,
    /// Request-Response for the snapshot bootstrap protocol
    /// (spec 11-snapshot-sync.md). Serves cached state snapshots so new
    /// nodes can skip block-by-block Klever scanning.
    pub snapshot: SnapshotCodec,
    /// Request-Response for the channel-history reconciliation
    /// protocol (spec 1 §channel-history-reconciliation, l2-node
    /// 0.47.0+). Used to backfill an empty `CHANNEL_MSGS` index on
    /// cold-join. Wire types in [`super::reconcile`].
    pub reconcile: ReconcileCodec,
}

/// Build the libp2p swarm with all configured behaviours.
pub fn build_swarm(config: &Config, keypair: Keypair) -> Result<Swarm<OgmaraBehaviour>> {
    let peer_id = keypair.public().to_peer_id();

    // Connection limits (enforces max_peers from config)
    let connection_limits = libp2p::connection_limits::Behaviour::new(
        libp2p::connection_limits::ConnectionLimits::default()
            .with_max_established(Some(config.network.max_peers))
            .with_max_established_incoming(Some(config.network.max_peers / 2))
            .with_max_established_per_peer(Some(2)),  // prevent per-peer connection exhaustion
    );

    // GossipSub configuration — mesh parameters tuned for small networks.
    // Defaults require mesh_n_low=5 peers to form a mesh, which is impossible
    // with fewer than 5 nodes. Messages won't propagate without a mesh.
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(262144) // 256 KB max message
        .mesh_n(3)                 // target 3 peers in mesh (default: 6)
        .mesh_n_low(1)             // form mesh with as few as 1 peer (default: 5)
        .mesh_n_high(6)            // cap at 6 (default: 12)
        // B4 fix proper (mainnet-blockers-fix-plan.md step 6, l2-node
        // 0.48.4). Was `1`. `mesh_outbound_min` is the minimum number
        // of *outbound* (we-dialed-them) peers gossipsub requires in a
        // topic mesh; if unmet, GRAFT is withheld and `publish` returns
        // `NoPeersSubscribedToTopic` even though inbound peers are
        // subscribed. On Ogmara's small / asymmetric testnet meshes a
        // node behind NAT (or one that only ever received dials) holds
        // *only* inbound connections, so `mesh_outbound_min = 1` made
        // its publishes silently fail — exactly the asymmetric
        // propagation the 0.46.6 instrumentation confirmed (one side
        // receives but never delivers). Setting it to `0` lets such a
        // node form a mesh and publish over its inbound links. The
        // tradeoff is weaker eclipse-attack resistance (an attacker
        // controlling all of a victim's inbound peers could sink its
        // mesh), but that defense only bites at mesh sizes Ogmara does
        // not yet reach, and "messages actually propagate" outranks a
        // large-mesh hardening at this scale. The inbound/outbound
        // balance is observable via `/admin/network/peer-telemetry`.
        .mesh_outbound_min(0)      // tolerate inbound-only meshes (B4)
        // Spec 13 §10.3 + v0.48.0: defer relay until each topic's
        // handler reports a validation outcome. Without this flag,
        // gossipsub auto-relays every well-formed envelope before
        // payload validation runs, allowing bad presence records to
        // reach every mesh peer one hop before rejection. With the
        // flag enabled, ALL topic handlers MUST call
        // `gossipsub.report_message_validation_result(msg_id, source,
        // MessageAcceptance::{Accept,Reject,Ignore})` for every
        // received message — see `NetworkService::run` and
        // `handle_swarm_event` in mod.rs.
        .validate_messages()
        .build()
        .map_err(|e| anyhow::anyhow!("gossipsub config error: {}", e))?;

    let gossipsub = gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config,
    )
    .map_err(|e| anyhow::anyhow!("gossipsub behaviour error: {}", e))?;

    // Kademlia DHT — protocol includes network_id for cross-network isolation
    let kad_protocol = format!("/ogmara/{}/kad/1.0.0", config.network_id());
    let kademlia = {
        let store = MemoryStore::new(peer_id);
        let mut kconfig = kad::Config::new(
            libp2p::StreamProtocol::try_from_owned(kad_protocol)
                .map_err(|e| anyhow::anyhow!("invalid Kademlia protocol string: {}", e))?,
        );
        kconfig.set_query_timeout(Duration::from_secs(30));
        kad::Behaviour::with_config(peer_id, store, kconfig)
    };

    // mDNS (local network discovery)
    let mdns = libp2p::mdns::tokio::Behaviour::new(
        libp2p::mdns::Config::default(),
        peer_id,
    )
    .context("creating mDNS behaviour")?;

    // Identify protocol — protocol_version includes network_id so peers on
    // different networks (testnet vs mainnet) reject each other at handshake.
    let identify = libp2p::identify::Behaviour::new(
        libp2p::identify::Config::new(
            format!("/ogmara/{}/1.0.0", config.network_id()),
            keypair.public(),
        )
        .with_agent_version(format!("ogmara-node/{}", env!("CARGO_PKG_VERSION"))),
    );

    // Request-Response for sync protocol — includes network_id
    let sync_protocol = format!("/ogmara/{}/sync/1.0.0", config.network_id());
    let request_response =
        libp2p::request_response::cbor::Behaviour::<
            super::sync::SyncRequest,
            super::sync::SyncResponse,
        >::new(
            [(
                libp2p::StreamProtocol::try_from_owned(sync_protocol)
                    .map_err(|e| anyhow::anyhow!("invalid sync protocol string: {}", e))?,
                libp2p::request_response::ProtocolSupport::Full,
            )],
            libp2p::request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30)),
        );

    // Snapshot protocol — separate request-response codec with:
    //  - longer request timeout (chunks can be a few MiB compressed),
    //  - response size cap raised above default 10 MiB to fit MAX_CHUNK_BYTES,
    //  - request size cap kept near default — requests are tiny.
    // Inbound is gated by config.snapshot.serve_enabled; outbound stays
    // available so Phase 2/3 clients can still negotiate the protocol.
    let snapshot_protocol = format!("/ogmara/{}/snapshot/1.0.0", config.network_id());
    let snapshot_support = if config.snapshot.serve_enabled {
        libp2p::request_response::ProtocolSupport::Full
    } else {
        libp2p::request_response::ProtocolSupport::Outbound
    };
    // Allow ~MAX_CHUNK_BYTES + framing overhead for the response, and
    // MAX_MANIFEST_BYTES for the request (covers GetManifest responses
    // and any future Phase-2 requests that include large quorum metadata).
    let snapshot_codec = libp2p::request_response::cbor::codec::Codec::<
        super::snapshot::SnapshotRequest,
        super::snapshot::SnapshotResponse,
    >::default()
        .set_request_size_maximum(super::snapshot::MAX_MANIFEST_BYTES as u64)
        .set_response_size_maximum(
            (super::snapshot::MAX_CHUNK_BYTES as u64).saturating_add(64 * 1024),
        );
    let snapshot = libp2p::request_response::Behaviour::with_codec(
        snapshot_codec,
        [(
            libp2p::StreamProtocol::try_from_owned(snapshot_protocol)
                .map_err(|e| anyhow::anyhow!("invalid snapshot protocol string: {}", e))?,
            snapshot_support,
        )],
        libp2p::request_response::Config::default()
            .with_request_timeout(Duration::from_secs(60)),
    );

    // Channel-history reconciliation protocol (spec 1, l2-node
    // 0.47.0+). Third request-response codec alongside `sync` and
    // `snapshot`. Inbound is gated on `[backfill] enabled` so
    // operators who disabled backfill don't serve requests; outbound
    // stays available regardless.
    let reconcile_protocol = format!(
        "/ogmara/{}/channel-reconcile/1.0.0",
        config.network_id()
    );
    let reconcile_support = if config.backfill.enabled {
        libp2p::request_response::ProtocolSupport::Full
    } else {
        libp2p::request_response::ProtocolSupport::Outbound
    };
    let reconcile = libp2p::request_response::cbor::Behaviour::<
        super::reconcile::ReconcileRequest,
        super::reconcile::ReconcileResponse,
    >::new(
        [(
            libp2p::StreamProtocol::try_from_owned(reconcile_protocol)
                .map_err(|e| anyhow::anyhow!("invalid reconcile protocol string: {}", e))?,
            reconcile_support,
        )],
        libp2p::request_response::Config::default()
            .with_request_timeout(Duration::from_secs(45)),
    );

    let behaviour = OgmaraBehaviour {
        connection_limits,
        gossipsub,
        kademlia,
        mdns,
        identify,
        request_response,
        snapshot,
        reconcile,
    };

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .context("configuring TCP transport")?
        .with_quic()
        .with_dns()
        .context("configuring DNS transport")?
        .with_behaviour(|_| Ok(behaviour))
        .context("configuring behaviour")?
        .with_swarm_config(|cfg: libp2p::swarm::Config| {
            cfg.with_idle_connection_timeout(Duration::from_secs(300)) // 5 min — 60s was too aggressive
        })
        .build();

    info_log_peer_id(&swarm);

    Ok(swarm)
}

fn info_log_peer_id(swarm: &Swarm<OgmaraBehaviour>) {
    tracing::info!(
        peer_id = %swarm.local_peer_id(),
        "Swarm created"
    );
}
