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

/// Derive a Klever address (klv1...) from an Ed25519 public key.
pub fn pubkey_to_address(pubkey: &VerifyingKey) -> Result<String, CryptoError> {
    let hrp = bech32::Hrp::parse("klv").expect("valid hrp");
    bech32::encode::<bech32::Bech32>(hrp, pubkey.as_bytes())
        .map_err(|e| CryptoError::Bech32Error(e.to_string()))
}

/// Decode a Klever address (klv1...) to raw 32-byte public key bytes.
pub fn address_to_pubkey_bytes(address: &str) -> Result<[u8; 32], CryptoError> {
    let (hrp, data) = bech32::decode(address)
        .map_err(|e| CryptoError::InvalidAddress(e.to_string()))?;

    if hrp.as_str() != "klv" {
        return Err(CryptoError::InvalidAddress(format!(
            "expected 'klv' prefix, got '{}'",
            hrp
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

/// Decode a Klever address to a VerifyingKey.
pub fn address_to_verifying_key(address: &str) -> Result<VerifyingKey, CryptoError> {
    let bytes = address_to_pubkey_bytes(address)?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))
}

/// Generate a new random Ed25519 key pair for node identity.
pub fn generate_keypair() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

/// Compute the message ID: Keccak-256(author_address_bytes + payload_bytes + timestamp_bytes).
pub fn compute_msg_id(author_pubkey: &[u8; 32], payload_bytes: &[u8], timestamp: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + payload_bytes.len() + 8);
    data.extend_from_slice(author_pubkey);
    data.extend_from_slice(payload_bytes);
    data.extend_from_slice(&timestamp.to_be_bytes());
    keccak256(&data)
}
