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

use super::sync::SyncCodec;

/// The composed network behaviour for the Ogmara node.
#[derive(NetworkBehaviour)]
pub struct OgmaraBehaviour {
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
}

/// Build the libp2p swarm with all configured behaviours.
pub fn build_swarm(config: &Config, keypair: Keypair) -> Result<Swarm<OgmaraBehaviour>> {
    let peer_id = keypair.public().to_peer_id();

    // GossipSub configuration
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(262144) // 256 KB max message
        .build()
        .map_err(|e| anyhow::anyhow!("gossipsub config error: {}", e))?;

    let gossipsub = gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(keypair.clone()),
        gossipsub_config,
    )
    .map_err(|e| anyhow::anyhow!("gossipsub behaviour error: {}", e))?;

    // Kademlia DHT
    let kademlia = {
        let store = MemoryStore::new(peer_id);
        let mut config = kad::Config::new(
            libp2p::StreamProtocol::new("/ogmara/kad/1.0.0"),
        );
        config.set_query_timeout(Duration::from_secs(30));
        kad::Behaviour::with_config(peer_id, store, config)
    };

    // mDNS (local network discovery)
    let mdns = libp2p::mdns::tokio::Behaviour::new(
        libp2p::mdns::Config::default(),
        peer_id,
    )
    .context("creating mDNS behaviour")?;

    // Identify protocol
    let identify = libp2p::identify::Behaviour::new(
        libp2p::identify::Config::new(
            "/ogmara/1.0.0".to_string(),
            keypair.public(),
        )
        .with_agent_version(format!("ogmara-node/{}", env!("CARGO_PKG_VERSION"))),
    );

    // Request-Response for sync protocol
    let request_response =
        libp2p::request_response::cbor::Behaviour::<
            super::sync::SyncRequest,
            super::sync::SyncResponse,
        >::new(
            [(
                libp2p::StreamProtocol::new("/ogmara/sync/1.0.0"),
                libp2p::request_response::ProtocolSupport::Full,
            )],
            libp2p::request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30)),
        );

    let behaviour = OgmaraBehaviour {
        gossipsub,
        kademlia,
        mdns,
        identify,
        request_response,
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
        .with_behaviour(|_| Ok(behaviour))
        .context("configuring behaviour")?
        .with_swarm_config(|cfg: libp2p::swarm::Config| {
            cfg.with_idle_connection_timeout(Duration::from_secs(60))
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
