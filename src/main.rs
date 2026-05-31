//! Ogmara L2 Node — entry point.
//!
//! A node in the Ogmara decentralized chat and news network.
//! Stores messages, relays data between peers, and serves client connections.

mod config;
mod crypto;
mod messages;
mod node;
mod pow;
mod storage;

// Phase 2+ stubs
mod api;
mod chain;
mod ipfs;
mod metrics;
mod network;
mod notifications;
mod trusted_proxies;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser)]
#[command(name = "ogmara-node")]
#[command(about = "Ogmara L2 network node — decentralized chat and news on Klever blockchain")]
#[command(version)]
struct Cli {
    /// Path to configuration file.
    /// Checked in order: provided path, /etc/ogmara/ogmara.toml, ./ogmara.toml
    #[arg(short, long, default_value = "ogmara.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// Resolve the config file path — tries the provided path first, then common locations.
fn resolve_config(path: &std::path::Path) -> PathBuf {
    if path.exists() {
        return path.to_path_buf();
    }
    // Try common system locations
    let alternatives = [
        std::path::PathBuf::from("/etc/ogmara/ogmara.toml"),
        std::path::PathBuf::from("/etc/ogmara-node/ogmara.toml"),
    ];
    for alt in &alternatives {
        if alt.exists() {
            return alt.clone();
        }
    }
    // Return original path (will fail with a clear error message)
    path.to_path_buf()
}

#[derive(Subcommand)]
enum Commands {
    /// Start the node (default).
    Run,
    /// Generate a default configuration file.
    Init {
        /// Output path for the config file.
        #[arg(short, long, default_value = "ogmara.toml")]
        output: PathBuf,
    },
    /// Show the node's identity (address, node ID, public key).
    Identity,
    /// Export the node's private key to a file for backup.
    ///
    /// WARNING: The exported file contains your node's private key.
    /// Anyone with this key can impersonate your node and spend its funds.
    /// Store it securely and never share it.
    ExportKey {
        /// Output file path for the key backup.
        #[arg(short, long, default_value = "ogmara-node-key.bak")]
        output: PathBuf,
    },
    /// Import a previously exported private key into the node's database.
    ///
    /// This replaces the current node identity. The node will restart with
    /// the imported key's address and node ID. Use this to restore a backup
    /// or migrate to a new server.
    ImportKey {
        /// Path to the key backup file.
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Clear all peer-directory entries (operator recovery from stale
    /// PEER_DIRECTORY state).
    ///
    /// Deletes every `pa:<peer_id> → multiaddr` row in the PEER_DIRECTORY
    /// column family. Use this when a stale entry has poisoned dial
    /// behaviour (e.g., a peer's recorded address points at localhost or
    /// some other unreachable host because of an old test colocation, or
    /// the operator-published metadata was wrong at the time it was
    /// persisted). On next startup `sc_discovery` re-populates the
    /// directory from on-chain metadata.
    ///
    /// **Requires the node to be stopped** — RocksDB cannot be opened
    /// for writes while the node holds the lock. Re-start the node after
    /// running this command.
    ///
    /// Shipped in l2-node 0.47.1 alongside the
    /// `sc_discovery::persist_multiaddr` overwrite-stale fix that
    /// prevents the same poisoning from recurring.
    ClearPeerDirectory {
        /// Skip the confirmation prompt. Use only in automation.
        #[arg(long)]
        yes: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Run) {
        Commands::Init { output } => {
            if output.exists() {
                anyhow::bail!("{} already exists, refusing to overwrite", output.display());
            }
            std::fs::write(&output, config::Config::default_toml())?;
            println!("Created default config at {}", output.display());
            Ok(())
        }

        Commands::Run => {
            let config_path = resolve_config(&cli.config);
            let cfg = config::Config::load(&config_path)?;
            init_logging(&cfg.logging);
            info!("Ogmara L2 Node v{}", env!("CARGO_PKG_VERSION"));

            let node = node::Node::init(cfg).await?;
            node.run().await
        }

        Commands::Identity => {
            let config_path = resolve_config(&cli.config);
            let cfg = config::Config::load(&config_path)?;

            // Read key using read-only DB access (works while node is running)
            let db_path = cfg.node.data_dir.join("db");
            match storage::rocks::Storage::read_node_key_readonly(&db_path)? {
                Some(key_bytes) => {
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
                    let node_id = {
                        use sha2::{Digest, Sha256};
                        let hash = Sha256::digest(signing_key.verifying_key().as_bytes());
                        bs58::encode(&hash[..20]).into_string()
                    };
                    println!("Node ID:     {}", node_id);
                    println!("Public Key:  {}", hex::encode(signing_key.verifying_key().as_bytes()));
                    match crypto::pubkey_to_address(&signing_key.verifying_key()) {
                        Ok(addr) => println!("Address:     {}", addr),
                        Err(e) => println!("Address:     error: {}", e),
                    }
                }
                None => {
                    println!("No node key found. Has the node been started at least once?");
                }
            }
            Ok(())
        }

        Commands::ExportKey { output } => {
            let config_path = resolve_config(&cli.config);
            let cfg = config::Config::load(&config_path)?;

            if output.exists() {
                anyhow::bail!(
                    "{} already exists — refusing to overwrite. \
                     Remove it first if you want to re-export.",
                    output.display()
                );
            }

            // Read key directly from RocksDB using read-only open — works
            // even while the node is running (no write lock needed).
            let db_path = cfg.node.data_dir.join("db");
            let key_bytes = storage::rocks::Storage::read_node_key_readonly(&db_path)
                .context("reading node key from database")?
                .ok_or_else(|| anyhow::anyhow!(
                    "no node key found in {}. Has the node been started at least once?",
                    db_path.display()
                ))?;

            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
            let address = crypto::pubkey_to_address(&signing_key.verifying_key())
                .unwrap_or_else(|_| "unknown".to_string());
            let node_id = {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(signing_key.verifying_key().as_bytes());
                bs58::encode(&hash[..20]).into_string()
            };

            let key_hex = hex::encode(signing_key.to_bytes());
            let content = format!(
                "# Ogmara Node Key Backup\n\
                 # Address: {}\n\
                 # Node ID: {}\n\
                 # WARNING: This file contains your node's PRIVATE KEY.\n\
                 # Anyone with this key can impersonate your node and spend its funds.\n\
                 # Store securely. Never share. Never commit to git.\n\
                 {}\n",
                address, node_id, key_hex
            );

            std::fs::write(&output, content.as_bytes())?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))?;
            }

            println!("Key exported to: {}", output.display());
            println!("Address:         {}", address);
            println!("Node ID:         {}", node_id);
            println!();
            println!("WARNING: Store this file securely. It contains your node's private key.");
            println!("         Anyone with this file can impersonate your node and spend its funds.");
            Ok(())
        }

        Commands::ImportKey { input } => {
            let config_path = resolve_config(&cli.config);
            let cfg = config::Config::load(&config_path)?;
            init_logging(&cfg.logging);

            if !input.exists() {
                anyhow::bail!("Key file not found: {}", input.display());
            }

            // Read and parse key file (skip comment lines, find 64-char hex line)
            let content = std::fs::read_to_string(&input)?;
            let key_hex = content
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty() && !line.starts_with('#'))
                .ok_or_else(|| anyhow::anyhow!("no key found in file (expected 64-char hex line)"))?;

            let key_bytes = hex::decode(key_hex)
                .map_err(|e| anyhow::anyhow!("invalid hex in key file: {}", e))?;
            if key_bytes.len() != 32 {
                anyhow::bail!("key must be 32 bytes (64 hex chars), got {} bytes", key_bytes.len());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_bytes);
            let imported_key = ed25519_dalek::SigningKey::from_bytes(&arr);
            // Zeroize intermediate material
            arr.fill(0);

            let imported_address = crypto::pubkey_to_address(&imported_key.verifying_key())
                .map_err(|e| anyhow::anyhow!("computing address from imported key: {}", e))?;

            // Store in the node's database
            let node = node::Node::init(cfg).await?;
            let current_address = node.address().unwrap_or_default();

            if current_address == imported_address {
                println!("Key already matches current node identity. No change needed.");
                return Ok(());
            }

            // Overwrite the key in storage
            node.storage.put_cf(
                storage::schema::cf::NODE_STATE,
                storage::schema::state_keys::NODE_PRIVATE_KEY,
                imported_key.as_bytes(),
            )?;

            println!("Key imported successfully!");
            println!("Previous address: {}", current_address);
            println!("New address:      {}", imported_address);
            println!();
            println!("Restart the node for the new identity to take effect.");
            Ok(())
        }

        Commands::ClearPeerDirectory { yes } => {
            let config_path = resolve_config(&cli.config);
            let cfg = config::Config::load(&config_path)?;
            let db_path = cfg.node.data_dir.join("db");

            if !yes {
                println!(
                    "About to clear ALL peer-directory entries in {}.",
                    db_path.display()
                );
                println!(
                    "On next startup, sc_discovery will re-populate \
                     the directory from on-chain metadata."
                );
                print!("Continue? [y/N]: ");
                use std::io::Write;
                std::io::stdout().flush().ok();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                let answer = line.trim().to_ascii_lowercase();
                if answer != "y" && answer != "yes" {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            // Storage::open() takes a write lock; if the node is
            // running, this errors with a clear message.
            let storage = storage::rocks::Storage::open(&db_path)
                .context(
                    "opening database for write — is the node still running? \
                     Stop it first with `sudo systemctl stop ogmara-node` and \
                     re-run this command.",
                )?;

            // Iterate the `pa:<peer_id>` prefix and delete each row.
            // We cap at 10_000 entries for safety — the v0.46.5 cap is
            // 256, so anything beyond that is a corruption signal but
            // we still want a finite bound.
            const SCAN_CAP: usize = 10_000;
            let rows = storage.prefix_iter_cf(
                storage::schema::cf::PEER_DIRECTORY,
                b"pa:",
                SCAN_CAP,
            )?;

            let total = rows.len();
            let mut deleted = 0usize;
            let mut failed = 0usize;
            for (key, _value) in rows {
                match storage.delete_cf(
                    storage::schema::cf::PEER_DIRECTORY,
                    &key,
                ) {
                    Ok(()) => deleted += 1,
                    Err(e) => {
                        failed += 1;
                        eprintln!(
                            "warning: failed to delete row (continuing): {}",
                            e
                        );
                    }
                }
            }

            println!(
                "Cleared {} of {} peer-directory entries{}.",
                deleted,
                total,
                if failed > 0 {
                    format!(" ({} failed)", failed)
                } else {
                    String::new()
                }
            );
            println!("Start the node to re-populate via sc_discovery.");
            Ok(())
        }
    }
}

/// Initialize the tracing subscriber based on logging config.
fn init_logging(logging: &config::LoggingConfig) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&logging.level));

    match logging.format.as_str() {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .init();
        }
    }
}
