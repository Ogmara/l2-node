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
        let latest = self.get_latest_block_height().await?;

        if latest <= self.last_block {
            return Ok(());
        }

        debug!(
            from = self.last_block + 1,
            to = latest,
            "Scanning blocks"
        );

        // Process blocks in batches — scan wide ranges per API call
        let batch_size = 500u64;
        let mut current = self.last_block + 1;

        while current <= latest {
            let end = (current + batch_size - 1).min(latest);

            if let Err(e) = self.process_block_range(current, end).await {
                warn!(from = current, to = end, error = %e, "Failed to process block range");
                return Ok(());
            }

            // Update cursor after successful batch
            self.last_block = end;
            self.storage.set_chain_cursor(end)?;
            current = end + 1;
        }

        Ok(())
    }

    /// Get the latest block height from the Klever API.
    ///
    /// Uses the API block list endpoint (not the node status endpoint)
    /// to avoid aggressive rate limiting on node.testnet.klever.org.
    async fn get_latest_block_height(&self) -> Result<u64> {
        let url = format!("{}/v1.0/block/list?limit=1", self.config.api_url);

        let response = self
            .http
            .get(&url)
            .send()
            .await
            .context("fetching block list")?;

        let status = response.status();
        let text = response.text().await.context("reading block list body")?;

        if !status.is_success() {
            anyhow::bail!(
                "block list HTTP {}: {}",
                status,
                &text[..text.len().min(200)]
            );
        }

        let resp: serde_json::Value =
            serde_json::from_str(&text).context("parsing block list JSON")?;

        let height = resp
            .pointer("/data/blocks/0/nonce")
            .and_then(|v| v.as_u64())
            .context("extracting block height from API")?;

        Ok(height)
    }

    /// Process a range of blocks — fetch transactions and filter for Ogmara SC events.
    async fn process_block_range(&self, start: u64, end: u64) -> Result<()> {
        let url = format!(
            "{}/v1.0/transaction/list?status=success&page=1&limit=100&startBlock={}&endBlock={}",
            self.config.api_url, start, end
        );

        let response = self
            .http
            .get(&url)
            .send()
            .await
            .context("fetching block transactions")?;

        let status = response.status();
        let text = response.text().await.context("reading transactions body")?;

        if !status.is_success() {
            anyhow::bail!(
                "transaction list HTTP {}: {}",
                status,
                &text[..text.len().min(200)]
            );
        }

        let resp: serde_json::Value =
            serde_json::from_str(&text).context("parsing block transactions JSON")?;

        // Extract transactions array
        let txs = match resp.pointer("/data/transactions") {
            Some(serde_json::Value::Array(arr)) => arr,
            _ => return Ok(()), // No transactions in this range
        };

        for tx_value in txs {
            let tx: KleverTransaction = match serde_json::from_value(tx_value.clone()) {
                Ok(tx) => tx,
                Err(_) => continue,
            };

            // Filter for successful SC invoke transactions targeting our contract
            if tx.status != "success" {
                continue;
            }

            let contract_address = tx
                .contract
                .first()
                .map(|c| c.parameter.address.as_str())
                .unwrap_or("");

            if contract_address != self.config.contract_address {
                continue;
            }

            // Decode the SC function call from the data field
            // data[0] is hex-encoded "functionName@arg1@arg2"
            let call_data = match tx.data.first() {
                Some(hex_data) => {
                    match hex::decode(hex_data) {
                        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                        Err(_) => continue,
                    }
                }
                None => continue,
            };

            if let Some(event) = parser::parse_sc_call(&call_data, &tx.sender, tx.timestamp) {
                if let Err(e) = self.handle_event(event).await {
                    warn!(
                        block = start,
                        tx = %tx.hash,
                        error = %e,
                        "Failed to handle SC event"
                    );
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
                // Merge with existing record to preserve profile data (display_name, avatar, bio).
                // The chain scanner may re-process blocks, so this must be idempotent.
                if let Some(existing) = self.storage.get_cf(cf::USERS, address.as_bytes())? {
                    // Record exists — only update registration fields, preserve profile
                    let mut record: UserRecord = serde_json::from_slice(&existing)?;
                    record.public_key = public_key;
                    record.registered_at = timestamp;
                    let bytes = serde_json::to_vec(&record)?;
                    self.storage
                        .put_cf(cf::USERS, address.as_bytes(), &bytes)?;
                    info!(address = %address, "User registration updated (on-chain, preserved profile)");
                } else {
                    // New user — create fresh record
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
                    self.storage.increment_stat(
                        crate::storage::schema::state_keys::TOTAL_USERS,
                    )?;
                    info!(address = %address, "User registered (on-chain)");
                }
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
                channel_id: _,
                creator,
                slug,
                channel_type,
                timestamp,
            } => {
                // Resolve the actual channel_id from the SC via getChannelBySlug view query
                let channel_id = match self.query_channel_id_by_slug(&slug).await {
                    Ok(id) => id,
                    Err(e) => {
                        warn!(slug = %slug, error = %e, "Failed to resolve channel_id — skipping");
                        return Ok(());
                    }
                };

                let channel_key = channel_id.to_be_bytes();

                // Skip channels that were intentionally deleted (tombstone check)
                if self.storage.exists_cf(cf::DELETED_CHANNELS, &channel_key)? {
                    tracing::trace!(channel_id, "Skipping deleted channel (tombstone exists)");
                    return Ok(());
                }

                // Only increment counter for genuinely new channels (idempotent on re-scan)
                let is_new = !self.storage.exists_cf(cf::CHANNELS, &channel_key)?;

                // If L2 ChannelCreate envelope already stored metadata (with display_name
                // and description), preserve those fields. The chain scanner only knows
                // what's on-chain (slug, type, creator), not the L2-only fields.
                let (display_name, description, member_count) = if !is_new {
                    if let Ok(Some(existing)) = self.storage.get_cf(cf::CHANNELS, &channel_key) {
                        if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&existing) {
                            (
                                meta.get("display_name").and_then(|v| v.as_str()).map(String::from),
                                meta.get("description").and_then(|v| v.as_str()).map(String::from),
                                meta.get("member_count").and_then(|v| v.as_u64()).unwrap_or(0),
                            )
                        } else {
                            (None, None, 0)
                        }
                    } else {
                        (None, None, 0)
                    }
                } else {
                    (None, None, 0)
                };

                let record = ChannelRecord {
                    channel_id,
                    slug,
                    creator,
                    channel_type,
                    created_at: timestamp,
                    display_name,
                    description,
                    member_count,
                };
                let bytes = serde_json::to_vec(&record)?;
                self.storage
                    .put_cf(cf::CHANNELS, &channel_key, &bytes)?;
                if is_new {
                    self.storage.increment_stat(
                        crate::storage::schema::state_keys::TOTAL_CHANNELS,
                    )?;

                    // Add creator as first member with "creator" role
                    let member_key = crate::storage::schema::encode_channel_member_key(
                        channel_id, &record.creator,
                    );
                    let member_record = serde_json::json!({
                        "joined_at": timestamp,
                        "role": "creator",
                    });
                    if let Ok(member_bytes) = serde_json::to_vec(&member_record) {
                        let _ = self.storage.put_cf(cf::CHANNEL_MEMBERS, &member_key, &member_bytes);
                    }
                }
                info!(channel_id, slug = %record.slug, "Channel created (on-chain)");
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

                // Also write DEVICE_WALLET_MAP so identity resolution works.
                // Convert hex pubkey → klv1 address for the map key.
                if let Ok(pubkey_bytes) = hex::decode(&device_key) {
                    if pubkey_bytes.len() == 32 {
                        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(
                            &<[u8; 32]>::try_from(pubkey_bytes.as_slice()).unwrap(),
                        ) {
                            if let Ok(device_address) = crate::crypto::pubkey_to_address(&vk) {
                                let _ = self.storage.put_cf(
                                    cf::DEVICE_WALLET_MAP,
                                    device_address.as_bytes(),
                                    user.as_bytes(),
                                );
                                // Also write reverse mapping
                                let wd_key = crate::storage::schema::encode_wallet_device_key(
                                    &user, &device_address,
                                );
                                let claim = serde_json::json!({
                                    "device_address": device_address,
                                    "wallet_address": user,
                                    "created_at": timestamp,
                                });
                                if let Ok(claim_bytes) = serde_json::to_vec(&claim) {
                                    let _ = self.storage.put_cf(
                                        cf::WALLET_DEVICES, &wd_key, &claim_bytes,
                                    );
                                }
                            }
                        }
                    }
                }

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

            ScEvent::TipSent {
                sender, recipient, amount, ..
            } => {
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

    /// Query the SC for a channel's ID by its slug via the VM hex endpoint.
    async fn query_channel_id_by_slug(&self, slug: &str) -> Result<u64> {
        let slug_hex = hex::encode(slug);
        let url = format!("{}/vm/hex", self.config.node_url);

        let body = serde_json::json!({
            "scAddress": self.config.contract_address,
            "funcName": "getChannelBySlug",
            "args": [slug_hex]
        });

        let resp: serde_json::Value = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("querying getChannelBySlug")?
            .json()
            .await
            .context("parsing getChannelBySlug response")?;

        let hex_data = resp
            .pointer("/data/data")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if hex_data.is_empty() {
            anyhow::bail!("getChannelBySlug returned empty for slug '{}'", slug);
        }

        // Decode variable-length big-endian u64
        let bytes = hex::decode(hex_data)
            .context("decoding channel ID hex")?;
        if bytes.len() > 8 {
            anyhow::bail!("channel ID too large: {} bytes", bytes.len());
        }
        let mut padded = [0u8; 8];
        padded[8 - bytes.len()..].copy_from_slice(&bytes);
        Ok(u64::from_be_bytes(padded))
    }
}
