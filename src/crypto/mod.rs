//! Cryptographic primitives for the Ogmara protocol.
//!
//! Implements Ed25519 signing/verification in all three formats:
//! - Klever message signing (wallet UI, auth headers)
//! - Klever transaction signing (on-chain operations)
//! - Ogmara protocol signing (node-to-node L2 messages)
//!
//! Also provides Keccak-256 hashing, bech32 address encoding, and
//! X25519 key derivation for DM encryption.

pub mod merkle;
pub mod signing;

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
use thiserror::Error;

/// Bech32 human-readable prefix for Klever wallet addresses (klv1...).
pub const WALLET_HRP: &str = "klv";

/// Bech32 human-readable prefix for Ogmara device key addresses (ogd1...).
/// Device keys are ephemeral Ed25519 keys delegated by a wallet.
/// Using a distinct prefix prevents confusion with wallet addresses.
pub const DEVICE_HRP: &str = "ogd";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("bech32 encoding error: {0}")]
    Bech32Error(String),
}

/// Compute Keccak-256 hash of the given data.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Derive a Klever wallet address (klv1...) from an Ed25519 public key.
pub fn pubkey_to_address(pubkey: &VerifyingKey) -> Result<String, CryptoError> {
    let hrp = bech32::Hrp::parse(WALLET_HRP).expect("valid hrp");
    bech32::encode::<bech32::Bech32>(hrp, pubkey.as_bytes())
        .map_err(|e| CryptoError::Bech32Error(e.to_string()))
}

/// Derive an Ogmara device address (ogd1...) from an Ed25519 public key.
///
/// Device keys are ephemeral keys delegated by a wallet. The distinct `ogd`
/// prefix makes them visually distinguishable from wallet addresses (`klv1`).
pub fn device_pubkey_to_address(pubkey: &VerifyingKey) -> Result<String, CryptoError> {
    let hrp = bech32::Hrp::parse(DEVICE_HRP).expect("valid hrp");
    bech32::encode::<bech32::Bech32>(hrp, pubkey.as_bytes())
        .map_err(|e| CryptoError::Bech32Error(e.to_string()))
}

/// Decode a bech32 address (klv1... or ogd1...) to raw 32-byte public key bytes.
///
/// Accepts both Klever wallet addresses and Ogmara device addresses.
pub fn address_to_pubkey_bytes(address: &str) -> Result<[u8; 32], CryptoError> {
    let (hrp, data) = bech32::decode(address)
        .map_err(|e| CryptoError::InvalidAddress(e.to_string()))?;

    let hrp_str = hrp.as_str();
    if hrp_str != WALLET_HRP && hrp_str != DEVICE_HRP {
        return Err(CryptoError::InvalidAddress(format!(
            "expected '{}' or '{}' prefix, got '{}'",
            WALLET_HRP, DEVICE_HRP, hrp_str
        )));
    }

    if data.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            got: data.len(),
        });
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data);
    Ok(bytes)
}

/// Decode a bech32 address (klv1... or ogd1...) to a VerifyingKey.
pub fn address_to_verifying_key(address: &str) -> Result<VerifyingKey, CryptoError> {
    let bytes = address_to_pubkey_bytes(address)?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))
}

/// Check whether an address uses the device HRP (ogd1...).
pub fn is_device_address(address: &str) -> bool {
    address.starts_with("ogd1")
}

/// Derive the Ogmara `node_id` (Base58-encoded SHA-256[..20] of the
/// 32-byte raw public key) from a bech32 wallet/device address. This
/// matches the derivation used by `NodeAnnouncement` (verifying that
/// `payload.node_id == derived(author)` in
/// [`crate::messages::router`]), the snapshot envelope authorship
/// path, and the on-startup `node_id` computation in
/// [`crate::node`]. Centralised in one helper so callers don't drift.
///
/// Used by the v0.46.7 media peer-fallback path: SC `getActiveNodes`
/// returns klv1 wallet addresses; the local `PEER_DIRECTORY` (where
/// `NodeAnnouncement` REST-endpoint records live) is keyed by
/// `node_id`. This helper bridges the two ID spaces deterministically
/// without any round-trip.
pub fn address_to_node_id(address: &str) -> Result<String, CryptoError> {
    use sha2::{Digest, Sha256};
    let pubkey_bytes = address_to_pubkey_bytes(address)?;
    let hash = Sha256::digest(pubkey_bytes);
    Ok(bs58::encode(&hash[..20]).into_string())
}

/// Generate a new random Ed25519 key pair for node identity.
pub fn generate_keypair() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

/// Compute a deterministic DM conversation ID from two Klever addresses.
///
/// Sorts the addresses lexicographically and hashes them with Keccak-256.
/// Both the Rust and TypeScript implementations must produce identical output.
pub fn compute_conversation_id(addr_a: &str, addr_b: &str) -> [u8; 32] {
    let (first, second) = if addr_a <= addr_b {
        (addr_a, addr_b)
    } else {
        (addr_b, addr_a)
    };
    let mut data = Vec::with_capacity(first.len() + second.len());
    data.extend_from_slice(first.as_bytes());
    data.extend_from_slice(second.as_bytes());
    keccak256(&data)
}

/// Compute a deterministic 32-byte key scope for an encrypted channel (P2 OECK).
///
/// `keccak256("ogmara-channel-scope-v1" || channel_id_be8)`. The domain prefix
/// keeps it disjoint from DM `conversation_id` scopes (which hash bech32 address
/// strings) so the two key spaces can never collide. Both the Rust and TypeScript
/// implementations must produce identical output.
pub fn compute_channel_scope(channel_id: u64) -> [u8; 32] {
    const DOMAIN: &[u8] = b"ogmara-channel-scope-v1";
    let mut data = Vec::with_capacity(DOMAIN.len() + 8);
    data.extend_from_slice(DOMAIN);
    data.extend_from_slice(&channel_id.to_be_bytes());
    keccak256(&data)
}

/// Compute the message ID: Keccak-256(author_address_bytes + payload_bytes + timestamp_bytes).
pub fn compute_msg_id(author_pubkey: &[u8; 32], payload_bytes: &[u8], timestamp: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + payload_bytes.len() + 8);
    data.extend_from_slice(author_pubkey);
    data.extend_from_slice(payload_bytes);
    data.extend_from_slice(&timestamp.to_be_bytes());
    keccak256(&data)
}

#[cfg(test)]
mod channel_scope_tests {
    use super::*;

    #[test]
    fn channel_scope_is_deterministic() {
        assert_eq!(compute_channel_scope(42), compute_channel_scope(42));
    }

    #[test]
    fn channel_scope_differs_per_channel() {
        assert_ne!(compute_channel_scope(1), compute_channel_scope(2));
    }

    #[test]
    fn channel_scope_domain_separated_from_dm() {
        // A DM conversation_id hashes bech32 address strings; a channel scope hashes
        // a domain tag + u64. They must never collide for any plausible input.
        let dm = compute_conversation_id("klv1aaaa", "klv1bbbb");
        assert_ne!(dm, compute_channel_scope(0));
        assert_ne!(dm, compute_channel_scope(1));
    }

    #[test]
    fn channel_scope_known_answer() {
        // Lock the wire format: keccak256("ogmara-channel-scope-v1" || 1u64_be).
        use sha3::{Digest, Keccak256};
        let mut h = Keccak256::new();
        h.update(b"ogmara-channel-scope-v1");
        h.update(1u64.to_be_bytes());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(compute_channel_scope(1), expected);
    }
}
