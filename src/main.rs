//! Ogmara L2 Node — entry point.
//!
//! A node in the Ogmara decentralized chat and news network.
//! Stores messages, relays data between peers, and serves client connections.

mod config;
mod crypto;
mod messages;
mod node;
mod storage;

// Phase 2+ stubs
mod api;
mod chain;
mod ipfs;
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
