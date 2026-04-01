//! Top-level node orchestration.
//!
//! Manages the lifecycle of all node components: storage, networking,
//! chain scanner, IPFS client, API server, and notification engine.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use tracing::{info, warn};

use crate::config::Config;
use crate::crypto;
use crate::storage::rocks::Storage;
use crate::storage::schema::state_keys;

/// The running L2 node instance.
pub struct Node {
    /// Node configuration.
    pub config: Config,
    /// Persistent storage (RocksDB).
    pub storage: Storage,
    /// Node's Ed25519 signing key (for node-to-node communication).
    pub signing_key: SigningKey,
    /// Node ID: Base58(SHA-256(public_key)[:20]).
    pub node_id: String,
    /// Local Lamport clock counter (atomic for concurrent access).
    pub lamport_counter: Arc<AtomicU64>,
    /// Shutdown signal sender.
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl Node {
    /// Initialize a new node from configuration.
    ///
    /// Opens storage, loads or generates the node identity key,
    /// and prepares all components for startup.
    pub async fn init(config: Config) -> Result<Self> {
        // Ensure data directory exists with restrictive permissions
        let data_dir = &config.node.data_dir;
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("creating data directory: {}", data_dir.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(data_dir, perms)
                .with_context(|| "setting data directory permissions")?;
        }

        // Open storage
        let db_path = data_dir.join("db");
        let storage =
            Storage::open(&db_path).with_context(|| "opening RocksDB storage")?;

        // Load or generate node identity key
        let signing_key = load_or_generate_key(&storage)?;
        let node_id = compute_node_id(&signing_key);

        // Rebuild stat counters if they're zero but data exists
        // (handles first upgrade from pre-stats versions)
        let has_v2_counters = storage.get_stat(state_keys::COUNTERS_V2)? > 0;
        if !has_v2_counters {
            if let Err(e) = storage.rebuild_stat_counters() {
                warn!(error = %e, "Failed to rebuild stat counters");
            }
        }

        // Load Lamport counter from storage
        let lamport_value = storage.get_lamport_counter()?;
        let lamport_counter = Arc::new(AtomicU64::new(lamport_value));

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

        info!(
            node_id = %node_id,
            data_dir = %data_dir.display(),
            "Node initialized"
        );

        Ok(Self {
            config,
            storage,
            signing_key,
            node_id,
            lamport_counter,
            shutdown_tx,
        })
    }

    /// Get the node's public key.
    pub fn public_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the node's Klever address.
    pub fn address(&self) -> Result<String> {
        crypto::pubkey_to_address(&self.public_key())
            .map_err(|e| anyhow::anyhow!("computing node address: {}", e))
    }

    /// Increment and return the next Lamport timestamp.
    pub fn next_lamport_ts(&self) -> u64 {
        self.lamport_counter.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Update the Lamport counter based on a received timestamp.
    ///
    /// Atomically sets counter = max(current, received) + 1 using CAS loop.
    pub fn update_lamport_ts(&self, received: u64) {
        loop {
            let current = self.lamport_counter.load(Ordering::SeqCst);
            let new_val = current.max(received) + 1;
            if self
                .lamport_counter
                .compare_exchange(current, new_val, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Get a receiver for the shutdown signal.
    pub fn shutdown_rx(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Signal all components to shut down.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Convert the node's Ed25519 signing key to a libp2p identity keypair.
    pub fn libp2p_keypair(&self) -> Result<libp2p::identity::Keypair> {
        let secret_bytes = self.signing_key.to_bytes();
        let libp2p_key = libp2p::identity::ed25519::Keypair::try_from_bytes(
            &mut [secret_bytes, *self.signing_key.verifying_key().as_bytes()].concat(),
        )
        .context("converting Ed25519 key to libp2p keypair")?;
        Ok(libp2p::identity::Keypair::from(libp2p_key))
    }

    /// Run the node until shutdown is signaled.
    ///
    /// Starts the network layer, message router, and all background tasks.
    pub async fn run(&self) -> Result<()> {
        info!(node_id = %self.node_id, "Starting Ogmara L2 node");

        // Initialize identity resolver (device → wallet mapping cache)
        let identity = crate::storage::identity::IdentityResolver::new(self.storage.clone());
        match identity.warm_cache() {
            Ok(count) if count > 0 => info!(count, "Identity cache warmed"),
            Ok(_) => {}
            Err(e) => warn!(error = %e, "Failed to warm identity cache"),
        }

        // Start the network service
        let keypair = self.libp2p_keypair()?;
        let mut network = crate::network::NetworkService::new(
            &self.config,
            self.storage.clone(),
            identity.clone(),
            keypair,
        )
        .await
        .context("starting network service")?;

        info!(
            peer_id = %network.local_peer_id(),
            "Network service started"
        );

        // Subscribe to pinned channels
        for &channel_id in &self.config.storage.pinned_channels {
            network.subscribe_channel(channel_id);
        }

        // Persist Lamport counter periodically
        let storage = self.storage.clone();
        let lamport = self.lamport_counter.clone();
        let mut lamport_shutdown_rx = self.shutdown_rx();

        let lamport_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let val = lamport.load(Ordering::SeqCst);
                        if let Err(e) = storage.set_lamport_counter(val) {
                            warn!(error = %e, "Failed to persist Lamport counter");
                        }
                    }
                    _ = lamport_shutdown_rx.recv() => break,
                }
            }
        });

        // Run network event loop in a task
        let network_shutdown_rx = self.shutdown_rx();
        let network_task = tokio::spawn(async move {
            network.run(network_shutdown_rx).await;
        });

        // Start chain scanner
        let chain_config = self.config.klever.clone();
        let chain_storage = self.storage.clone();
        let chain_shutdown_rx = self.shutdown_rx();
        let chain_task = tokio::spawn(async move {
            match crate::chain::scanner::ChainScanner::new(chain_config, chain_storage) {
                Ok(mut scanner) => scanner.run(chain_shutdown_rx).await,
                Err(e) => warn!(error = %e, "Failed to start chain scanner"),
            }
        });

        // IPFS client (stored for API media endpoints)
        let ipfs_client = match crate::ipfs::client::IpfsClient::new(&self.config.ipfs) {
            Ok(ipfs) => {
                match ipfs.health_check().await {
                    Ok(true) => {
                        info!("IPFS node connected");
                        Some(ipfs)
                    }
                    Ok(false) => {
                        warn!("IPFS node not reachable at {}", self.config.ipfs.api_url);
                        Some(ipfs) // keep client — node may come online later
                    }
                    Err(e) => {
                        warn!(error = %e, "IPFS health check failed");
                        Some(ipfs)
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to create IPFS client");
                None
            }
        };

        // Start REST/WS API server
        let api_router = crate::messages::router::MessageRouter::new(
            self.storage.clone(),
            identity.clone(),
            self.config.api.rate_limit_per_ip,
        );
        // Derive Klever network name from configured node URL
        let klever_network = if self.config.klever.node_url.contains("testnet") {
            "testnet".to_string()
        } else if self.config.klever.node_url.is_empty() {
            "unknown".to_string()
        } else {
            "mainnet".to_string()
        };

        let app_state = Arc::new(crate::api::state::AppState::new(
            self.storage.clone(),
            api_router,
            self.node_id.clone(),
            klever_network,
            self.config.klever.contract_address.clone(),
            ipfs_client,
            identity.clone(),
        ));
        let api_config = self.config.clone();
        let api_shutdown_rx = self.shutdown_rx();
        let api_task = tokio::spawn(async move {
            if let Err(e) = crate::api::start_api_server(&api_config, app_state, api_shutdown_rx).await {
                tracing::error!(error = %e, "API server error");
            }
        });

        // Wait for shutdown signal (Ctrl+C)
        let mut shutdown_rx = self.shutdown_rx();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down...");
            }
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received");
            }
        }

        self.shutdown();

        // Persist final Lamport counter
        let val = self.lamport_counter.load(Ordering::SeqCst);
        self.storage.set_lamport_counter(val)?;

        lamport_task.abort();
        network_task.abort();
        chain_task.abort();
        api_task.abort();

        info!("Node stopped");
        Ok(())
    }
}

/// Load the node's Ed25519 signing key from storage, or generate a new one.
fn load_or_generate_key(storage: &Storage) -> Result<SigningKey> {
    match storage.get_cf(
        crate::storage::schema::cf::NODE_STATE,
        state_keys::NODE_PRIVATE_KEY,
    )? {
        Some(bytes) if bytes.len() == 32 => {
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            let key = SigningKey::from_bytes(&key_bytes);
            info!("Loaded existing node identity key");
            Ok(key)
        }
        _ => {
            let key = crypto::generate_keypair();
            storage.put_cf(
                crate::storage::schema::cf::NODE_STATE,
                state_keys::NODE_PRIVATE_KEY,
                key.as_bytes(),
            )?;
            info!("Generated new node identity key");
            Ok(key)
        }
    }
}

/// Compute the node ID: Base58(SHA-256(public_key)[:20]).
fn compute_node_id(signing_key: &SigningKey) -> String {
    use sha2::{Digest, Sha256};
    let pubkey = signing_key.verifying_key();
    let hash = Sha256::digest(pubkey.as_bytes());
    // Take first 20 bytes and encode as base58
    bs58::encode(&hash[..20]).into_string()
}
