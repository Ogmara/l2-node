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

    /// Run the node until shutdown is signaled.
    ///
    /// Starts all components and waits for a shutdown signal (Ctrl+C or explicit).
    pub async fn run(&self) -> Result<()> {
        info!(node_id = %self.node_id, "Starting Ogmara L2 node");

        // Persist Lamport counter periodically
        let storage = self.storage.clone();
        let lamport = self.lamport_counter.clone();
        let mut shutdown_rx = self.shutdown_rx();

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
                    _ = shutdown_rx.recv() => break,
                }
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
