//! Proof-of-Work anti-spam system.
//!
//! Unknown wallets (not on-chain registered and not previously seen) must solve
//! a SHA-256 hash puzzle before their first message is accepted. This creates
//! computational cost for Sybil attacks while being a one-time ~2-3 second cost
//! for legitimate users.
//!
//! Flow:
//! 1. New wallet sends message → node checks KNOWN_WALLETS CF
//! 2. Unknown + not registered → message rejected with PoW challenge
//! 3. Client solves challenge and submits solution via `/api/v1/pow/verify`
//! 4. Node verifies → marks wallet as "known" in RocksDB → client retries message
//! 5. All future messages from this wallet skip PoW

use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::config::PowConfig;
use crate::storage::rocks::Storage;
use crate::storage::schema::cf;

/// A pending PoW challenge issued to a wallet.
#[derive(Debug, Clone)]
struct PendingChallenge {
    /// The wallet address this challenge was issued for.
    address: String,
    /// The challenge prefix (hex-encoded SHA-256 hash).
    prefix: String,
    /// When this challenge expires (Unix ms).
    expires_at: u64,
    /// Difficulty (leading zero bits).
    difficulty: u8,
}

/// PoW challenge response sent to clients.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PowChallenge {
    /// Unique challenge ID.
    pub challenge_id: String,
    /// Hex-encoded prefix to hash with the nonce.
    pub prefix: String,
    /// Number of leading zero bits required.
    pub difficulty: u8,
    /// Challenge expiry (Unix timestamp seconds).
    pub expires_at: u64,
}

/// PoW solution submitted by a client.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PowSolution {
    /// The challenge ID being solved.
    pub challenge_id: String,
    /// The wallet address (klv1... or ogd1...) claiming this solution.
    pub address: String,
    /// The nonce that produces the required leading zero bits.
    pub nonce: u64,
}

/// Manages PoW challenges and known wallet tracking.
pub struct PowManager {
    config: PowConfig,
    storage: Storage,
    /// Pending challenges: challenge_id → PendingChallenge.
    pending: DashMap<String, PendingChallenge>,
}

impl PowManager {
    pub fn new(config: PowConfig, storage: Storage) -> Self {
        Self {
            config,
            storage,
            pending: DashMap::new(),
        }
    }

    /// Check if a wallet is known (has solved PoW or is on-chain registered).
    pub fn is_wallet_known(&self, address: &str) -> bool {
        if !self.config.enabled {
            return true; // PoW disabled — all wallets pass
        }

        // Check KNOWN_WALLETS CF in RocksDB
        match self.storage.get_cf(cf::KNOWN_WALLETS, address.as_bytes()) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                warn!(error = %e, address, "Failed to check known wallet, allowing");
                true // fail open to avoid blocking legitimate users on storage errors
            }
        }
    }

    /// Mark a wallet as known (persisted in RocksDB, survives restarts).
    pub fn mark_wallet_known(&self, address: &str) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if let Err(e) = self.storage.put_cf(
            cf::KNOWN_WALLETS,
            address.as_bytes(),
            &now_ms.to_be_bytes(),
        ) {
            warn!(error = %e, address, "Failed to persist known wallet");
        }

        debug!(address, "Wallet marked as known (PoW verified or registered)");
    }

    /// Maximum pending challenges per address to prevent memory exhaustion.
    const MAX_PENDING_PER_ADDRESS: usize = 3;
    /// Maximum total pending challenges to prevent global OOM.
    const MAX_PENDING_TOTAL: usize = 10_000;

    /// Generate a new PoW challenge for a wallet.
    ///
    /// Returns `None` if the pending challenge limits have been reached.
    pub fn generate_challenge(&self, address: &str) -> Option<PowChallenge> {
        // Global cap to prevent OOM under sustained attack
        if self.pending.len() >= Self::MAX_PENDING_TOTAL {
            warn!("PoW pending challenge limit reached ({}), rejecting", Self::MAX_PENDING_TOTAL);
            return None;
        }

        // Per-address cap to prevent challenge flooding for a single wallet
        let addr_count = self.pending.iter()
            .filter(|entry| entry.value().address == address)
            .count();
        if addr_count >= Self::MAX_PENDING_PER_ADDRESS {
            debug!(address, count = addr_count, "Max pending challenges for address");
            return None;
        }

        let challenge_id = uuid::Uuid::new_v4().to_string();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // prefix = SHA-256(address + challenge_id + timestamp)
        let mut hasher = Sha256::new();
        hasher.update(address.as_bytes());
        hasher.update(challenge_id.as_bytes());
        hasher.update(&now_ms.to_be_bytes());
        let prefix = hex::encode(hasher.finalize());

        let expires_at_ms = now_ms.saturating_add(self.config.challenge_ttl_seconds.saturating_mul(1000));
        let expires_at_secs = expires_at_ms / 1000;

        self.pending.insert(
            challenge_id.clone(),
            PendingChallenge {
                address: address.to_string(),
                prefix: prefix.clone(),
                expires_at: expires_at_ms,
                difficulty: self.config.difficulty,
            },
        );

        debug!(address, challenge_id = %challenge_id, "PoW challenge issued");

        Some(PowChallenge {
            challenge_id,
            prefix,
            difficulty: self.config.difficulty,
            expires_at: expires_at_secs,
        })
    }

    /// Verify a PoW solution. On success, marks the wallet as known.
    ///
    /// Returns Ok(()) on success, Err(reason) on failure.
    pub fn verify_solution(&self, solution: &PowSolution) -> Result<(), String> {
        // Validate address format (must be klv1... or ogd1... bech32)
        if !solution.address.starts_with("klv1") && !solution.address.starts_with("ogd1") {
            return Err("invalid address format".to_string());
        }
        if solution.address.len() < 10 || solution.address.len() > 100 {
            return Err("invalid address length".to_string());
        }

        // Look up the pending challenge
        let challenge = self
            .pending
            .remove(&solution.challenge_id)
            .map(|(_, v)| v)
            .ok_or_else(|| "unknown or expired challenge".to_string())?;

        // Verify the solution address matches the challenge address
        if challenge.address != solution.address {
            return Err("address mismatch: solution address does not match challenge".to_string());
        }

        // Check expiry
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if now_ms > challenge.expires_at {
            return Err("challenge expired".to_string());
        }

        // Verify: SHA-256(prefix + nonce) must have `difficulty` leading zero bits
        let mut hasher = Sha256::new();
        hasher.update(challenge.prefix.as_bytes());
        hasher.update(solution.nonce.to_le_bytes());
        let hash = hasher.finalize();

        if !has_leading_zeros(&hash, challenge.difficulty) {
            return Err(format!(
                "insufficient work: need {} leading zero bits",
                challenge.difficulty
            ));
        }

        // Solution valid — mark wallet as known
        self.mark_wallet_known(&solution.address);

        info!(
            address = %solution.address,
            challenge_id = %solution.challenge_id,
            nonce = solution.nonce,
            "PoW solution verified, wallet marked as known"
        );

        Ok(())
    }

    /// Remove expired challenges to prevent unbounded memory growth.
    /// Should be called periodically (e.g., every few minutes).
    pub fn cleanup_expired_challenges(&self) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let before = self.pending.len();
        self.pending.retain(|_, challenge| now_ms < challenge.expires_at);
        let evicted = before - self.pending.len();

        if evicted > 0 {
            debug!(evicted, remaining = self.pending.len(), "Cleaned up expired PoW challenges");
        }
    }

    /// Whether PoW is enabled in config.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Check if a hash has at least `n` leading zero bits.
fn has_leading_zeros(hash: &[u8], n: u8) -> bool {
    let full_bytes = (n / 8) as usize;
    let remaining_bits = n % 8;

    // Check full zero bytes
    if hash.len() < full_bytes {
        return false;
    }
    for byte in &hash[..full_bytes] {
        if *byte != 0 {
            return false;
        }
    }

    // Check remaining bits in the next byte
    if remaining_bits > 0 {
        if hash.len() <= full_bytes {
            return false;
        }
        let mask = 0xFF << (8 - remaining_bits);
        if hash[full_bytes] & mask != 0 {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_leading_zeros() {
        // All zeros
        assert!(has_leading_zeros(&[0x00, 0x00, 0x00], 24));
        assert!(has_leading_zeros(&[0x00, 0x00, 0x00], 20));

        // 20 leading zero bits = 2 full zero bytes + 4 zero bits
        // 0x00 0x00 0x0F = 20 leading zeros (0000_0000 0000_0000 0000_1111)
        assert!(has_leading_zeros(&[0x00, 0x00, 0x0F], 20));
        // 0x00 0x00 0x1F = 19 leading zeros
        assert!(!has_leading_zeros(&[0x00, 0x00, 0x1F], 20));

        // Edge cases
        assert!(has_leading_zeros(&[0x00], 8));
        assert!(!has_leading_zeros(&[0x01], 8));
        assert!(has_leading_zeros(&[0x7F], 1));
        assert!(!has_leading_zeros(&[0x80], 1));

        // Zero difficulty always passes
        assert!(has_leading_zeros(&[0xFF], 0));
    }
}
