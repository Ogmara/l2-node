//! SC event decoding — parse Klever receipts into typed Ogmara events.
//!
//! Decodes the indexed topics from smart contract receipts into
//! strongly-typed ScEvent variants (spec 02-onchain.md section 5).

use tracing::warn;

use super::types::{KleverReceipt, ScEvent};

/// Parse a Klever receipt into a typed ScEvent, if applicable.
///
/// Returns None if the receipt is not an Ogmara SC event or cannot be decoded.
pub fn parse_receipt(receipt: &KleverReceipt) -> Option<ScEvent> {
    match receipt.event_identifier.as_str() {
        "userRegistered" => parse_user_registered(receipt),
        "publicKeyUpdated" => parse_public_key_updated(receipt),
        "channelCreated" => parse_channel_created(receipt),
        "channelTransferred" => parse_channel_transferred(receipt),
        "deviceDelegated" => parse_device_delegated(receipt),
        "deviceRevoked" => parse_device_revoked(receipt),
        "stateAnchored" => parse_state_anchored(receipt),
        "tipSent" => parse_tip_sent(receipt),
        _ => None,
    }
}

fn parse_user_registered(receipt: &KleverReceipt) -> Option<ScEvent> {
    // Topics: [address, public_key, timestamp]
    if receipt.topics.len() < 3 {
        warn!(event = "userRegistered", "insufficient topics");
        return None;
    }
    Some(ScEvent::UserRegistered {
        address: decode_address(&receipt.topics[0])?,
        public_key: receipt.topics[1].clone(),
        timestamp: decode_u64(&receipt.topics[2])?,
    })
}

fn parse_public_key_updated(receipt: &KleverReceipt) -> Option<ScEvent> {
    if receipt.topics.len() < 2 {
        return None;
    }
    Some(ScEvent::PublicKeyUpdated {
        address: decode_address(&receipt.topics[0])?,
        public_key: receipt.topics[1].clone(),
    })
}

fn parse_channel_created(receipt: &KleverReceipt) -> Option<ScEvent> {
    // Topics: [channel_id, creator, slug, channel_type, timestamp]
    if receipt.topics.len() < 5 {
        warn!(event = "channelCreated", "insufficient topics");
        return None;
    }
    Some(ScEvent::ChannelCreated {
        channel_id: decode_u64(&receipt.topics[0])?,
        creator: decode_address(&receipt.topics[1])?,
        slug: decode_string(&receipt.topics[2])?,
        channel_type: decode_u8(&receipt.topics[3])?,
        timestamp: decode_u64(&receipt.topics[4])?,
    })
}

fn parse_channel_transferred(receipt: &KleverReceipt) -> Option<ScEvent> {
    if receipt.topics.len() < 3 {
        return None;
    }
    Some(ScEvent::ChannelTransferred {
        channel_id: decode_u64(&receipt.topics[0])?,
        from: decode_address(&receipt.topics[1])?,
        to: decode_address(&receipt.topics[2])?,
    })
}

fn parse_device_delegated(receipt: &KleverReceipt) -> Option<ScEvent> {
    if receipt.topics.len() < 5 {
        return None;
    }
    Some(ScEvent::DeviceDelegated {
        user: decode_address(&receipt.topics[0])?,
        device_key: receipt.topics[1].clone(),
        permissions: decode_u8(&receipt.topics[2])?,
        expires_at: decode_u64(&receipt.topics[3])?,
        timestamp: decode_u64(&receipt.topics[4])?,
    })
}

fn parse_device_revoked(receipt: &KleverReceipt) -> Option<ScEvent> {
    if receipt.topics.len() < 3 {
        return None;
    }
    Some(ScEvent::DeviceRevoked {
        user: decode_address(&receipt.topics[0])?,
        device_key: receipt.topics[1].clone(),
        timestamp: decode_u64(&receipt.topics[2])?,
    })
}

fn parse_state_anchored(receipt: &KleverReceipt) -> Option<ScEvent> {
    if receipt.topics.len() < 7 {
        return None;
    }
    Some(ScEvent::StateAnchored {
        block_height: decode_u64(&receipt.topics[0])?,
        state_root: receipt.topics[1].clone(),
        message_count: decode_u64(&receipt.topics[2])?,
        channel_count: decode_u32(&receipt.topics[3])?,
        user_count: decode_u32(&receipt.topics[4])?,
        node_id: decode_string(&receipt.topics[5])?,
        timestamp: decode_u64(&receipt.topics[6])?,
    })
}

fn parse_tip_sent(receipt: &KleverReceipt) -> Option<ScEvent> {
    if receipt.topics.len() < 7 {
        return None;
    }
    Some(ScEvent::TipSent {
        sender: decode_address(&receipt.topics[0])?,
        recipient: decode_address(&receipt.topics[1])?,
        amount: decode_u64(&receipt.topics[2])?,
        msg_id: receipt.topics[3].clone(),
        channel_id: decode_u64(&receipt.topics[4])?,
        note: decode_string(&receipt.topics[5])?,
        timestamp: decode_u64(&receipt.topics[6])?,
    })
}

// --- Decoding helpers ---

/// Decode a hex-encoded Klever address from an event topic.
fn decode_address(hex_topic: &str) -> Option<String> {
    let bytes = hex::decode(hex_topic).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let hrp = bech32::Hrp::parse("klv").ok()?;
    bech32::encode::<bech32::Bech32>(hrp, &bytes).ok()
}

/// Decode a hex-encoded u64 from an event topic (big-endian).
fn decode_u64(hex_topic: &str) -> Option<u64> {
    let bytes = hex::decode(hex_topic).ok()?;
    // Klever SC may emit variable-length big-endian integers
    let mut padded = [0u8; 8];
    if bytes.len() > 8 {
        return None;
    }
    padded[8 - bytes.len()..].copy_from_slice(&bytes);
    Some(u64::from_be_bytes(padded))
}

/// Decode a hex-encoded u32 (rejects values > u32::MAX).
fn decode_u32(hex_topic: &str) -> Option<u32> {
    let v = decode_u64(hex_topic)?;
    u32::try_from(v).ok()
}

/// Decode a hex-encoded u8 (rejects values > u8::MAX).
fn decode_u8(hex_topic: &str) -> Option<u8> {
    let v = decode_u64(hex_topic)?;
    u8::try_from(v).ok()
}

/// Decode a hex-encoded UTF-8 string.
fn decode_string(hex_topic: &str) -> Option<String> {
    let bytes = hex::decode(hex_topic).ok()?;
    String::from_utf8(bytes).ok()
}
