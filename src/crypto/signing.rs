//! Ed25519 signature creation and verification in all Ogmara signing formats.
//!
//! Three formats (see protocol spec 4.1):
//! - Klever message: prefix + length + message → Keccak-256 → Ed25519
//! - Klever transaction: Ed25519 sign raw tx_hash directly
//! - Ogmara protocol: domain separator + envelope fields → Keccak-256 → Ed25519

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use super::{keccak256, CryptoError};

/// The Klever message signing prefix (from kos-rs).
/// `\x17` is 23 in decimal, matching the byte length of "Klever Signed Message:\n".
const KLEVER_MSG_PREFIX: &[u8] = b"\x17Klever Signed Message:\n";

/// The Ogmara protocol domain separator.
const OGMARA_DOMAIN_SEP: &[u8] = b"ogmara-msg:";

// --- Klever Message Signing (4.1.1) ---

/// Prepare a message for Klever message signing: prefix + length + message → Keccak-256.
pub fn klever_message_hash(message: &[u8]) -> [u8; 32] {
    let length_str = message.len().to_string();
    let mut data = Vec::with_capacity(KLEVER_MSG_PREFIX.len() + length_str.len() + message.len());
    data.extend_from_slice(KLEVER_MSG_PREFIX);
    data.extend_from_slice(length_str.as_bytes());
    data.extend_from_slice(message);
    keccak256(&data)
}

/// Sign a message using the Klever message signing format.
pub fn sign_klever_message(signing_key: &SigningKey, message: &[u8]) -> Signature {
    let hash = klever_message_hash(message);
    signing_key.sign(&hash)
}

/// Verify a Klever message signature.
pub fn verify_klever_message(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    let hash = klever_message_hash(message);
    verifying_key
        .verify(&hash, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

// --- Ogmara Protocol Signing (4.1.3) ---

/// Build the signed bytes for an Ogmara protocol message.
///
/// Format: "ogmara-msg:" + version(1) + msg_type(1) + msg_id(32) + timestamp(8) + payload
pub fn ogmara_signed_bytes(
    version: u8,
    msg_type: u8,
    msg_id: &[u8; 32],
    timestamp: u64,
    payload_bytes: &[u8],
) -> Vec<u8> {
    let mut data =
        Vec::with_capacity(OGMARA_DOMAIN_SEP.len() + 1 + 1 + 32 + 8 + payload_bytes.len());
    data.extend_from_slice(OGMARA_DOMAIN_SEP);
    data.push(version);
    data.push(msg_type);
    data.extend_from_slice(msg_id);
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(payload_bytes);
    data
}

/// Sign an Ogmara protocol message.
pub fn sign_ogmara_message(
    signing_key: &SigningKey,
    version: u8,
    msg_type: u8,
    msg_id: &[u8; 32],
    timestamp: u64,
    payload_bytes: &[u8],
) -> Signature {
    let signed_bytes = ogmara_signed_bytes(version, msg_type, msg_id, timestamp, payload_bytes);
    let hash = keccak256(&signed_bytes);
    signing_key.sign(&hash)
}

/// Verify an Ogmara protocol message signature.
pub fn verify_ogmara_message(
    verifying_key: &VerifyingKey,
    version: u8,
    msg_type: u8,
    msg_id: &[u8; 32],
    timestamp: u64,
    payload_bytes: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    let signed_bytes = ogmara_signed_bytes(version, msg_type, msg_id, timestamp, payload_bytes);
    let hash = keccak256(&signed_bytes);
    verifying_key
        .verify(&hash, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

// --- Klever Transaction Signing (4.1.2) ---

/// Sign a raw transaction hash (no prefix, no Keccak wrapper).
pub fn sign_tx_hash(signing_key: &SigningKey, tx_hash: &[u8; 32]) -> Signature {
    signing_key.sign(tx_hash)
}

/// Verify a transaction hash signature.
pub fn verify_tx_hash(
    verifying_key: &VerifyingKey,
    tx_hash: &[u8; 32],
    signature: &Signature,
) -> Result<(), CryptoError> {
    verifying_key
        .verify(tx_hash, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

// --- Auth Header Signing (L2 node spec 4.2) ---

/// Build the auth string for REST API authentication.
///
/// Format: "ogmara-auth:" + timestamp + ":" + method + ":" + path
pub fn build_auth_string(timestamp: u64, method: &str, path: &str) -> String {
    format!("ogmara-auth:{timestamp}:{method}:{path}")
}

/// Sign an auth header using Klever message format.
pub fn sign_auth_header(
    signing_key: &SigningKey,
    timestamp: u64,
    method: &str,
    path: &str,
) -> Signature {
    let auth_string = build_auth_string(timestamp, method, path);
    sign_klever_message(signing_key, auth_string.as_bytes())
}

/// Verify an auth header signature.
pub fn verify_auth_header(
    verifying_key: &VerifyingKey,
    timestamp: u64,
    method: &str,
    path: &str,
    signature: &Signature,
) -> Result<(), CryptoError> {
    let auth_string = build_auth_string(timestamp, method, path);
    verify_klever_message(verifying_key, auth_string.as_bytes(), signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_keypair() -> SigningKey {
        let mut rng = rand::rngs::OsRng;
        SigningKey::generate(&mut rng)
    }

    #[test]
    fn test_klever_message_sign_verify() {
        let key = test_keypair();
        let message = b"Hello Ogmara";
        let sig = sign_klever_message(&key, message);
        assert!(verify_klever_message(&key.verifying_key(), message, &sig).is_ok());
    }

    #[test]
    fn test_klever_message_wrong_key_fails() {
        let key1 = test_keypair();
        let key2 = test_keypair();
        let message = b"Hello Ogmara";
        let sig = sign_klever_message(&key1, message);
        assert!(verify_klever_message(&key2.verifying_key(), message, &sig).is_err());
    }

    #[test]
    fn test_ogmara_protocol_sign_verify() {
        let key = test_keypair();
        let msg_id = [42u8; 32];
        let timestamp = 1234567890u64;
        let payload = b"test payload";

        let sig = sign_ogmara_message(&key, 1, 0x01, &msg_id, timestamp, payload);
        assert!(
            verify_ogmara_message(&key.verifying_key(), 1, 0x01, &msg_id, timestamp, payload, &sig)
                .is_ok()
        );
    }

    #[test]
    fn test_ogmara_protocol_tampered_payload_fails() {
        let key = test_keypair();
        let msg_id = [42u8; 32];
        let timestamp = 1234567890u64;
        let payload = b"test payload";

        let sig = sign_ogmara_message(&key, 1, 0x01, &msg_id, timestamp, payload);
        assert!(verify_ogmara_message(
            &key.verifying_key(),
            1,
            0x01,
            &msg_id,
            timestamp,
            b"tampered",
            &sig,
        )
        .is_err());
    }

    #[test]
    fn test_auth_header_sign_verify() {
        let key = test_keypair();
        let timestamp = 1234567890u64;
        let sig = sign_auth_header(&key, timestamp, "GET", "/api/v1/health");
        assert!(
            verify_auth_header(&key.verifying_key(), timestamp, "GET", "/api/v1/health", &sig)
                .is_ok()
        );
    }

    #[test]
    fn test_tx_hash_sign_verify() {
        let key = test_keypair();
        let tx_hash = [99u8; 32];
        let sig = sign_tx_hash(&key, &tx_hash);
        assert!(verify_tx_hash(&key.verifying_key(), &tx_hash, &sig).is_ok());
    }
}
