//! Klever blockchain scanner — polls for new blocks and processes SC events.
//!
//! Monitors the Ogmara smart contract on Klever mainnet (or testnet) for
//! events like user registrations, channel creation, delegations, etc.
//! Updates local state in RocksDB accordingly (spec 03-l2-node.md section 3.2).

use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, error, info, warn};

use crate::config::KleverConfig;
use crate::storage::rocks::Storage;
use crate::storage::schema::cf;

use super::parser;
use super::types::*;

/// The chain scanner service.
pub struct ChainScanner {
    /// Klever RPC/API configuration.
    config: KleverConfig,
    /// HTTP client for Klever RPC calls.
    http: reqwest::Client,
    /// Persistent storage.
    storage: Storage,
    /// Last processed block height (cursor).
    last_block: u64,
}

impl ChainScanner {
    /// Create a new chain scanner.
    pub fn new(config: KleverConfig, storage: Storage) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("creating HTTP client")?;

        let last_block = storage.get_chain_cursor()?;

        info!(
            last_block,
            contract = %config.contract_address,
            "Chain scanner initialized"
        );

        Ok(Self {
            config,
            http,
            storage,
            last_block,
        })
    }

    /// Run the scanner loop until shutdown.
    pub async fn run(
        &mut self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        if self.config.node_url.is_empty()
            || self.config.api_url.is_empty()
            || self.config.contract_address.is_empty()
        {
            info!("Chain scanner disabled — Klever node_url, api_url, or contract_address not configured");
            // Wait for shutdown
            let _ = shutdown_rx.recv().await;
            return;
        }

        info!("Chain scanner started, polling every {}ms", self.config.scan_interval_ms);

        let interval_duration = Duration::from_millis(self.config.scan_interval_ms);
        let mut interval = tokio::time::interval(interval_duration);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.poll_blocks().await {
                        warn!(error = %e, "Chain scanner poll failed");
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Chain scanner shutting down");
                    break;
                }
            }
        }
    }

    /// Poll for new blocks since the last cursor position.
    async fn poll_blocks(&mut self) -> Result<()> {
        // Get the latest block height from Klever
        let latest = self.get_latest_block_height().await?;

        if latest <= self.last_block {
            return Ok(());
        }

        debug!(
            from = self.last_block + 1,
            to = latest,
            "Scanning blocks"
        );

        // Process blocks in batches (don't try to fetch too many at once)
        let batch_size = 10u64;
        let mut current = self.last_block + 1;

        while current <= latest {
            let end = (current + batch_size - 1).min(latest);

            for height in current..=end {
                if let Err(e) = self.process_block(height).await {
                    warn!(block = height, error = %e, "Failed to process block");
                    // Don't advance cursor past failed block
                    return Ok(());
                }
            }

            // Update cursor after successful batch
            self.last_block = end;
            self.storage.set_chain_cursor(end)?;
            current = end + 1;
        }

        Ok(())
    }

    /// Get the latest block height from Klever RPC.
    async fn get_latest_block_height(&self) -> Result<u64> {
        let url = format!("{}/node/status", self.config.node_url);
        let resp: serde_json::Value = self
            .http
            .get(&url)
            .send()
            .await
            .context("fetching node status")?
            .json()
            .await
            .context("parsing node status")?;

        // Klever node status returns block height in data.chainStatistics.liveTxCount
        // or data.chainStatistics.currentBlockNonce — exact path depends on API version
        let height = resp
            .pointer("/data/chainStatistics/currentBlockNonce")
            .or_else(|| resp.pointer("/data/overview/currentBlockNonce"))
            .and_then(|v| v.as_u64())
            .context("extracting block height from node status")?;

        Ok(height)
    }

    /// Process a single block — fetch transactions and filter for Ogmara SC events.
    async fn process_block(&self, height: u64) -> Result<()> {
        let url = format!(
            "{}/transaction/list?status=success&page=1&limit=100&startBlock={}&endBlock={}",
            self.config.api_url, height, height
        );

        let resp: serde_json::Value = self
            .http
            .get(&url)
            .send()
            .await
            .context("fetching block transactions")?
            .json()
            .await
            .context("parsing block transactions")?;

        // Extract transactions array
        let txs = match resp.pointer("/data/transactions") {
            Some(serde_json::Value::Array(arr)) => arr,
            _ => return Ok(()), // No transactions in this block
        };

        for tx_value in txs {
            // Check if this transaction targets our contract
            let tx: KleverTransaction = match serde_json::from_value(tx_value.clone()) {
                Ok(tx) => tx,
                Err(_) => continue,
            };

            // Filter for successful transactions with receipts
            if tx.status != "success" {
                continue;
            }

            for receipt in &tx.receipts {
                // Only process receipts from our contract
                if receipt.contract != self.config.contract_address {
                    continue;
                }

                if let Some(event) = parser::parse_receipt(receipt) {
                    if let Err(e) = self.handle_event(event).await {
                        warn!(
                            block = height,
                            tx = %tx.hash,
                            error = %e,
                            "Failed to handle SC event"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle a parsed SC event — update local state in RocksDB.
    async fn handle_event(&self, event: ScEvent) -> Result<()> {
        match event {
            ScEvent::UserRegistered {
                address,
                public_key,
                timestamp,
            } => {
                // Only increment counter for genuinely new users (idempotent on re-scan)
                let is_new = !self.storage.exists_cf(cf::USERS, address.as_bytes())?;
                let record = UserRecord {
                    address: address.clone(),
                    public_key,
                    registered_at: timestamp,
                    display_name: None,
                    avatar_cid: None,
                    bio: None,
                };
                let bytes = serde_json::to_vec(&record)?;
                self.storage
                    .put_cf(cf::USERS, address.as_bytes(), &bytes)?;
                if is_new {
                    self.storage.increment_stat(
                        crate::storage::schema::state_keys::TOTAL_USERS,
                    )?;
                }
                info!(address = %address, "User registered (on-chain)");
            }

            ScEvent::PublicKeyUpdated {
                address,
                public_key,
            } => {
                if let Some(existing) = self.storage.get_cf(cf::USERS, address.as_bytes())? {
                    let mut record: UserRecord = serde_json::from_slice(&existing)?;
                    record.public_key = public_key;
                    let bytes = serde_json::to_vec(&record)?;
                    self.storage
                        .put_cf(cf::USERS, address.as_bytes(), &bytes)?;
                    info!(address = %address, "Public key updated (on-chain)");
                } else {
                    warn!(address = %address, "PublicKeyUpdated for unknown user — may have missed registration event");
                }
            }

            ScEvent::ChannelCreated {
                channel_id,
                creator,
                slug,
                channel_type,
                timestamp,
            } => {
                // Only increment counter for genuinely new channels (idempotent on re-scan)
                let is_new = !self.storage.exists_cf(cf::CHANNELS, &channel_id.to_be_bytes())?;
                let record = ChannelRecord {
                    channel_id,
                    slug,
                    creator,
                    channel_type,
                    created_at: timestamp,
                    display_name: None,
                    description: None,
                    member_count: 0,
                };
                let bytes = serde_json::to_vec(&record)?;
                self.storage
                    .put_cf(cf::CHANNELS, &channel_id.to_be_bytes(), &bytes)?;
                if is_new {
                    self.storage.increment_stat(
                        crate::storage::schema::state_keys::TOTAL_CHANNELS,
                    )?;
                }
                info!(channel_id, "Channel created (on-chain)");
            }

            ScEvent::ChannelTransferred {
                channel_id,
                from: _,
                to,
            } => {
                if let Some(existing) =
                    self.storage
                        .get_cf(cf::CHANNELS, &channel_id.to_be_bytes())?
                {
                    let mut record: ChannelRecord = serde_json::from_slice(&existing)?;
                    record.creator = to;
                    let bytes = serde_json::to_vec(&record)?;
                    self.storage
                        .put_cf(cf::CHANNELS, &channel_id.to_be_bytes(), &bytes)?;
                    info!(channel_id, "Channel transferred (on-chain)");
                }
            }

            ScEvent::DeviceDelegated {
                user,
                device_key,
                permissions,
                expires_at,
                timestamp,
            } => {
                let record = DelegationRecord {
                    user_address: user.clone(),
                    device_pub_key: device_key.clone(),
                    permissions,
                    expires_at,
                    created_at: timestamp,
                    active: true,
                };
                let key = crate::storage::schema::encode_delegation_key(&user, &device_key);
                let bytes = serde_json::to_vec(&record)?;
                self.storage.put_cf(cf::DELEGATIONS, &key, &bytes)?;
                info!(user = %user, "Device delegated (on-chain)");
            }

            ScEvent::DeviceRevoked {
                user,
                device_key,
                timestamp: _,
            } => {
                let key = crate::storage::schema::encode_delegation_key(&user, &device_key);
                if let Some(existing) = self.storage.get_cf(cf::DELEGATIONS, &key)? {
                    let mut record: DelegationRecord = serde_json::from_slice(&existing)?;
                    record.active = false;
                    let bytes = serde_json::to_vec(&record)?;
                    self.storage.put_cf(cf::DELEGATIONS, &key, &bytes)?;
                    info!(user = %user, "Device revoked (on-chain)");
                }
            }

            ScEvent::StateAnchored {
                block_height,
                state_root,
                message_count,
                channel_count,
                user_count,
                node_id,
                timestamp,
            } => {
                let record = StateAnchorRecord {
                    block_height,
                    state_root,
                    message_count,
                    channel_count,
                    user_count,
                    node_id,
                    anchored_at: timestamp,
                };
                let bytes = serde_json::to_vec(&record)?;
                self.storage
                    .put_cf(cf::STATE_ANCHORS, &block_height.to_be_bytes(), &bytes)?;

                // Write anchor-by-node reverse index for verification badges
                let anchor_node_key = crate::storage::schema::encode_anchor_by_node_key(
                    &record.node_id,
                    record.anchored_at,
                );
                self.storage.put_cf(
                    cf::ANCHOR_BY_NODE,
                    &anchor_node_key,
                    &block_height.to_be_bytes(),
                )?;

                debug!(block_height, "State anchor recorded");
            }

            ScEvent::TipSent { sender, recipient, amount, .. } => {
                debug!(
                    sender = %sender,
                    recipient = %recipient,
                    amount,
                    "Tip sent (on-chain)"
                );
                // Tip notifications are handled by the notification engine
            }
        }

        Ok(())
    }
}
