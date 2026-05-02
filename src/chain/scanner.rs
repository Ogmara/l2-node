//! Klever blockchain scanner — polls for new blocks and processes SC events.
//!
//! Monitors the Ogmara smart contract on Klever mainnet (or testnet) for
//! events like user registrations, channel creation, delegations, etc.
//! Updates local state in RocksDB accordingly (spec 03-l2-node.md section 3.2).
//!
//! Rate-limit aware: uses exponential backoff on HTTP 429 responses and
//! inter-batch delays during catch-up to stay within Klever API quotas.

use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::config::KleverConfig;
use crate::storage::rocks::Storage;
use crate::storage::schema::cf;

use super::parser;
use super::types::*;

/// Minimum delay between batches during catch-up scanning (ms).
const CATCHUP_BATCH_DELAY_MS: u64 = 500;
/// Base backoff on rate limit (ms). Doubled on each consecutive 429.
const BACKOFF_BASE_MS: u64 = 5_000;
/// Maximum backoff cap (ms).
const BACKOFF_MAX_MS: u64 = 120_000;
/// Number of blocks per batch during catch-up.
const CATCHUP_BATCH_SIZE: u64 = 2_000;
/// Number of blocks per batch when near chain tip.
const TIP_BATCH_SIZE: u64 = 500;
/// If we're more than this many blocks behind, we're in catch-up mode.
const CATCHUP_THRESHOLD: u64 = 5_000;

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
    /// Current exponential backoff duration (reset on success).
    backoff: Duration,
    /// Number of consecutive rate-limit errors.
    consecutive_429s: u32,
    /// Channel to notify the network layer about new channel discoveries.
    /// The network service subscribes to the corresponding GossipSub topic.
    channel_tx: tokio::sync::mpsc::UnboundedSender<u64>,
}

impl ChainScanner {
    /// Create a new chain scanner.
    ///
    /// `channel_tx` notifies the network layer when new channels are discovered
    /// so it can subscribe to the corresponding GossipSub topics.
    pub fn new(
        config: KleverConfig,
        storage: Storage,
        channel_tx: tokio::sync::mpsc::UnboundedSender<u64>,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("creating HTTP client")?;

        let mut last_block = storage.get_chain_cursor()?;

        // If the cursor is 0 (fresh node) and start_block is configured,
        // skip ahead to avoid scanning millions of irrelevant blocks.
        if last_block == 0 && config.start_block > 0 {
            last_block = config.start_block;
            info!(
                start_block = config.start_block,
                contract = %config.contract_address,
                "Chain scanner skipping to start_block (fresh node)"
            );
        } else {
            info!(
                last_block,
                contract = %config.contract_address,
                "Chain scanner initialized"
            );
        }

        Ok(Self {
            config,
            http,
            storage,
            last_block,
            backoff: Duration::ZERO,
            consecutive_429s: 0,
            channel_tx,
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
            let _ = shutdown_rx.recv().await;
            return;
        }

        info!("Chain scanner started, polling every {}ms", self.config.scan_interval_ms);

        let interval_duration = Duration::from_millis(self.config.scan_interval_ms);
        let mut interval = tokio::time::interval(interval_duration);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // If we're in backoff, wait before trying
                    if !self.backoff.is_zero() {
                        info!(
                            backoff_secs = self.backoff.as_secs(),
                            consecutive_429s = self.consecutive_429s,
                            "Rate-limited, backing off"
                        );
                        tokio::select! {
                            _ = tokio::time::sleep(self.backoff) => {},
                            _ = shutdown_rx.recv() => {
                                info!("Chain scanner shutting down");
                                return;
                            }
                        }
                    }

                    match self.poll_blocks(&mut shutdown_rx).await {
                        Ok(()) => {
                            // Reset backoff on success
                            if self.consecutive_429s > 0 {
                                info!("Chain scanner recovered from rate limiting");
                            }
                            self.backoff = Duration::ZERO;
                            self.consecutive_429s = 0;
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("429") || err_str.contains("Too Many Requests") {
                                self.consecutive_429s += 1;
                                let backoff_ms = (BACKOFF_BASE_MS * 2u64.saturating_pow(self.consecutive_429s.saturating_sub(1)))
                                    .min(BACKOFF_MAX_MS);
                                self.backoff = Duration::from_millis(backoff_ms);
                                warn!(
                                    error = %e,
                                    backoff_ms,
                                    consecutive_429s = self.consecutive_429s,
                                    "Chain scanner rate-limited, will back off"
                                );
                            } else {
                                warn!(error = %e, "Chain scanner poll failed");
                            }
                        }
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
    async fn poll_blocks(
        &mut self,
        shutdown_rx: &mut tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        let latest = self.get_latest_block_height().await?;

        // Store chain tip for dashboard sync lag calculation (spec 10-dashboard.md §6)
        let _ = self.storage.put_cf(
            cf::NODE_STATE,
            crate::storage::schema::state_keys::CHAIN_TIP,
            &latest.to_be_bytes(),
        );

        if latest <= self.last_block {
            return Ok(());
        }

        let behind = latest - self.last_block;
        let catching_up = behind > CATCHUP_THRESHOLD;
        let batch_size = if catching_up { CATCHUP_BATCH_SIZE } else { TIP_BATCH_SIZE };

        if catching_up {
            info!(
                behind,
                from = self.last_block + 1,
                to = latest,
                batch_size,
                "Catch-up scan starting"
            );
        } else {
            debug!(
                from = self.last_block + 1,
                to = latest,
                "Scanning blocks"
            );
        }

        let mut current = self.last_block + 1;

        while current <= latest {
            let end = (current + batch_size - 1).min(latest);

            self.process_block_range(current, end).await?;

            // Update cursor after successful batch
            self.last_block = end;
            self.storage.set_chain_cursor(end)?;
            current = end + 1;

            // Inter-batch delay to avoid hitting rate limits
            if current <= latest {
                let delay = if catching_up {
                    Duration::from_millis(CATCHUP_BATCH_DELAY_MS)
                } else {
                    Duration::from_millis(200)
                };

                // Check for shutdown during the delay
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {},
                    _ = shutdown_rx.recv() => {
                        info!(
                            cursor = self.last_block,
                            "Chain scanner shutting down mid-scan"
                        );
                        return Ok(());
                    }
                }
            }
        }

        if catching_up {
            info!(cursor = self.last_block, "Catch-up scan complete");
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
    ///
    /// Paginates through the transaction list to ensure all transactions are captured
    /// even in busy block ranges. Capped at 50 pages to prevent infinite loops.
    async fn process_block_range(&self, start: u64, end: u64) -> Result<()> {
        let mut page = 1u64;
        const MAX_PAGES: u64 = 50;

        loop {
            if page > MAX_PAGES {
                warn!(start, end, "Hit pagination cap ({MAX_PAGES} pages) — some transactions may be missed");
                break;
            }
            let url = format!(
                "{}/v1.0/transaction/list?status=success&type=63&toAddress={}&page={}&limit=100&startBlock={}&endBlock={}",
                self.config.api_url, self.config.contract_address, page, start, end
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
                Some(serde_json::Value::Array(arr)) if !arr.is_empty() => arr,
                _ => break, // No (more) transactions
            };

            let tx_count = txs.len();

            for tx_value in txs {
                let tx: KleverTransaction = match serde_json::from_value(tx_value.clone()) {
                    Ok(tx) => tx,
                    Err(e) => {
                        debug!(error = %e, "Skipping unparseable transaction");
                        continue;
                    }
                };

                if tx.status != "success" {
                    continue;
                }

                // Already filtered by toAddress in the API query, but double-check
                // the contract call parameter address matches
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

            // If we got fewer than the limit, no more pages
            if tx_count < 100 {
                break;
            }
            page += 1;

            // Brief pause between pages
            tokio::time::sleep(Duration::from_millis(100)).await;
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

                // If a record already exists (from prior on-chain re-scan or L2
                // ChannelUpdate envelope), JSON-merge: overwrite only the
                // on-chain authoritative fields and preserve every L2-only
                // field (display_name, description, member_count, logo_cid,
                // banner_cid, website_url, tags, and anything added later).
                // This avoids dropping L2 metadata on re-scan, which previously
                // erased channel avatars/banners on public channels every time
                // the scanner re-processed their ChannelCreated event.
                let bytes = if let Ok(Some(existing)) = self.storage.get_cf(cf::CHANNELS, &channel_key) {
                    let mut meta = serde_json::from_slice::<serde_json::Value>(&existing)
                        .unwrap_or_else(|e| {
                            tracing::error!(
                                channel_id,
                                error = %e,
                                "CHANNELS record failed to parse as JSON — rebuilding from on-chain fields"
                            );
                            serde_json::json!({})
                        });
                    if let Some(obj) = meta.as_object_mut() {
                        obj.insert("channel_id".into(), serde_json::json!(channel_id));
                        obj.insert("slug".into(), serde_json::json!(slug.clone()));
                        obj.insert("creator".into(), serde_json::json!(creator.clone()));
                        obj.insert("channel_type".into(), serde_json::json!(channel_type));
                        obj.insert("created_at".into(), serde_json::json!(timestamp));
                        // Default missing L2-only fields without overwriting present ones
                        obj.entry("display_name").or_insert(serde_json::Value::Null);
                        obj.entry("description").or_insert(serde_json::Value::Null);
                        obj.entry("member_count").or_insert(serde_json::json!(0));
                        serde_json::to_vec(&meta)?
                    } else {
                        // Existing record is JSON but not an object — skip the
                        // merge (don't abort the whole batch) and keep going.
                        tracing::warn!(
                            channel_id,
                            "CHANNELS record is not a JSON object — skipping merge"
                        );
                        return Ok(());
                    }
                } else {
                    // First time we've seen this channel — write the canonical
                    // ChannelRecord with no L2 fields populated yet.
                    let record = ChannelRecord {
                        channel_id,
                        slug: slug.clone(),
                        creator: creator.clone(),
                        channel_type,
                        created_at: timestamp,
                        display_name: None,
                        description: None,
                        member_count: 0,
                    };
                    serde_json::to_vec(&record)?
                };
                self.storage
                    .put_cf(cf::CHANNELS, &channel_key, &bytes)?;
                if is_new {
                    self.storage.increment_stat(
                        crate::storage::schema::state_keys::TOTAL_CHANNELS,
                    )?;

                    // Add creator as first member with "creator" role
                    let member_key = crate::storage::schema::encode_channel_member_key(
                        channel_id, &creator,
                    );
                    let member_record = serde_json::json!({
                        "joined_at": timestamp,
                        "role": "creator",
                    });
                    if let Ok(member_bytes) = serde_json::to_vec(&member_record) {
                        let _ = self.storage.put_cf(cf::CHANNEL_MEMBERS, &member_key, &member_bytes);
                    }
                }
                // Notify network layer to subscribe to this channel's GossipSub topic
                let _ = self.channel_tx.send(channel_id);

                info!(channel_id, slug = %slug, "Channel created (on-chain)");
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
                    // JSON-merge to preserve L2-only fields (logo_cid, banner_cid,
                    // website_url, tags). Same rationale as ChannelCreated above:
                    // struct round-trip would silently drop them.
                    let mut meta = serde_json::from_slice::<serde_json::Value>(&existing)
                        .unwrap_or_else(|e| {
                            tracing::error!(
                                channel_id,
                                error = %e,
                                "CHANNELS record corrupted on transfer — rebuilding from on-chain fields"
                            );
                            serde_json::json!({})
                        });
                    if let Some(obj) = meta.as_object_mut() {
                        obj.insert("creator".into(), serde_json::json!(to));
                        let bytes = serde_json::to_vec(&meta)?;
                        self.storage
                            .put_cf(cf::CHANNELS, &channel_id.to_be_bytes(), &bytes)?;
                        info!(channel_id, "Channel transferred (on-chain)");
                    } else {
                        tracing::warn!(
                            channel_id,
                            "CHANNELS record is not a JSON object — skipping transfer write"
                        );
                    }
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
                // Convert hex pubkey → ogd1 device address for the map key.
                if let Ok(pubkey_bytes) = hex::decode(&device_key) {
                    if pubkey_bytes.len() == 32 {
                        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(
                            &<[u8; 32]>::try_from(pubkey_bytes.as_slice()).unwrap(),
                        ) {
                            if let Ok(device_address) = crate::crypto::device_pubkey_to_address(&vk) {
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
