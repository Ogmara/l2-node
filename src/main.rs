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

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser)]
#[command(name = "ogmara-node")]
#[command(about = "Ogmara L2 network node — decentralized chat and news on Klever blockchain")]
#[command(version)]
struct Cli {
    /// Path to configuration file.
    #[arg(short, long, default_value = "ogmara.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
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
            let cfg = config::Config::load(&cli.config)?;
            init_logging(&cfg.logging);
            info!("Ogmara L2 Node v{}", env!("CARGO_PKG_VERSION"));

            let node = node::Node::init(cfg).await?;
            node.run().await
        }

        Commands::Identity => {
            let cfg = config::Config::load(&cli.config)?;
            init_logging(&cfg.logging);

            let node = node::Node::init(cfg).await?;
            println!("Node ID:     {}", node.node_id);
            println!("Public Key:  {}", hex::encode(node.public_key().as_bytes()));
            match node.address() {
                Ok(addr) => println!("Address:     {}", addr),
                Err(e) => println!("Address:     error: {}", e),
            }
            Ok(())
        }

        Commands::ExportKey { output } => {
            let cfg = config::Config::load(&cli.config)?;
            init_logging(&cfg.logging);

            if output.exists() {
                anyhow::bail!(
                    "{} already exists — refusing to overwrite. \
                     Remove it first if you want to re-export.",
                    output.display()
                );
            }

            let node = node::Node::init(cfg).await?;
            let address = node.address().unwrap_or_else(|_| "unknown".to_string());

            // Write key as hex + address for verification
            let key_hex = hex::encode(node.signing_key.to_bytes());
            let content = format!(
                "# Ogmara Node Key Backup\n\
                 # Address: {}\n\
                 # Node ID: {}\n\
                 # WARNING: This file contains your node's PRIVATE KEY.\n\
                 # Anyone with this key can impersonate your node and spend its funds.\n\
                 # Store securely. Never share. Never commit to git.\n\
                 {}\n",
                address, node.node_id, key_hex
            );

            std::fs::write(&output, content.as_bytes())?;

            // Set restrictive permissions (owner-only read)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))?;
            }

            println!("Key exported to: {}", output.display());
            println!("Address:         {}", address);
            println!("Node ID:         {}", node.node_id);
            println!();
            println!("WARNING: Store this file securely. It contains your node's private key.");
            println!("         Anyone with this file can impersonate your node and spend its funds.");
            Ok(())
        }

        Commands::ImportKey { input } => {
            let cfg = config::Config::load(&cli.config)?;
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
