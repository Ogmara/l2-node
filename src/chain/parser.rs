//! SC event decoding — parse Klever transaction data into typed Ogmara events.
//!
//! Decodes the function call and arguments from the transaction `data` field.
//! Klever SC calls encode as: "functionName@hexArg1@hexArg2@..." in the data
//! field. The sender address comes from the transaction itself.

use tracing::warn;

use super::types::ScEvent;

/// Parse a decoded SC call string into a typed ScEvent.
///
/// `call_data` is the decoded (from hex) data field: "functionName@arg1@arg2@..."
/// `sender` is the transaction sender address (klv1...).
/// `timestamp` is the transaction timestamp (unix seconds).
///
/// Returns None if the call is not a recognized Ogmara SC function.
pub fn parse_sc_call(call_data: &str, sender: &str, timestamp: u64) -> Option<ScEvent> {
    let parts: Vec<&str> = call_data.split('@').collect();
    let function_name = parts.first()?;
    let args = &parts[1..];

    match *function_name {
        "register" => parse_register(args, sender, timestamp),
        "updatePublicKey" => parse_update_public_key(args, sender),
        "createChannel" => parse_create_channel(args, sender, timestamp),
        "transferChannel" => parse_transfer_channel(args, sender),
        "delegateDevice" => parse_delegate_device(args, sender, timestamp),
        "revokeDevice" => parse_revoke_device(args, sender, timestamp),
        "anchorState" => parse_anchor_state(args, timestamp),
        "tip" => parse_tip(args, sender, timestamp),
        // init, upgrade, admin endpoints — not events we need to track
        _ => None,
    }
}

fn parse_register(args: &[&str], sender: &str, timestamp: u64) -> Option<ScEvent> {
    // register(public_key: hex64)
    // args[0] = hex-encoded public key string (the SC stores this as-is)
    if args.is_empty() {
        warn!(event = "register", "missing public_key argument");
        return None;
    }
    // The arg is hex-of-hex: the original hex pubkey was hex-encoded again for the data field.
    // Decode the outer hex to get the original hex string.
    let public_key = decode_hex_string(args[0])?;
    Some(ScEvent::UserRegistered {
        address: sender.to_string(),
        public_key,
        timestamp,
    })
}

fn parse_update_public_key(args: &[&str], sender: &str) -> Option<ScEvent> {
    if args.is_empty() {
        return None;
    }
    let public_key = decode_hex_string(args[0])?;
    Some(ScEvent::PublicKeyUpdated {
        address: sender.to_string(),
        public_key,
    })
}

fn parse_create_channel(args: &[&str], sender: &str, timestamp: u64) -> Option<ScEvent> {
    // createChannel(slug: String, channel_type: u8)
    if args.len() < 2 {
        warn!(event = "createChannel", "insufficient arguments");
        return None;
    }
    let slug = decode_hex_string(args[0])?;
    let channel_type = decode_hex_u8(args[1])?;

    // We don't know the channel_id from the call alone — it's assigned by the SC.
    // We can query it from the SC view endpoint, or derive it from the next_channel_id
    // counter at the time. For now, we query the SC to get the actual channel_id.
    // Since we can't do async here, we'll store with a placeholder and resolve later,
    // or we can look at the return data.
    //
    // Simpler approach: query getChannelBySlug after seeing a createChannel call.
    // For now, emit with channel_id=0 — the scanner's handle_event can resolve it.
    Some(ScEvent::ChannelCreated {
        channel_id: 0, // resolved by scanner via SC view query
        creator: sender.to_string(),
        slug,
        channel_type,
        timestamp,
    })
}

fn parse_transfer_channel(args: &[&str], _sender: &str) -> Option<ScEvent> {
    // transferChannel(channel_id: u64, new_owner: Address)
    if args.len() < 2 {
        return None;
    }
    let channel_id = decode_hex_u64(args[0])?;
    let new_owner = decode_hex_address(args[1])?;
    Some(ScEvent::ChannelTransferred {
        channel_id,
        from: _sender.to_string(),
        to: new_owner,
    })
}

fn parse_delegate_device(args: &[&str], sender: &str, timestamp: u64) -> Option<ScEvent> {
    // delegateDevice(device_pub_key: hex64, permissions: u8, expires_at: u64)
    if args.len() < 3 {
        return None;
    }
    let device_key = decode_hex_string(args[0])?;
    let permissions = decode_hex_u8(args[1])?;
    let expires_at = decode_hex_u64(args[2])?;
    Some(ScEvent::DeviceDelegated {
        user: sender.to_string(),
        device_key,
        permissions,
        expires_at,
        timestamp,
    })
}

fn parse_revoke_device(args: &[&str], sender: &str, timestamp: u64) -> Option<ScEvent> {
    // revokeDevice(device_pub_key: hex64)
    if args.is_empty() {
        return None;
    }
    let device_key = decode_hex_string(args[0])?;
    Some(ScEvent::DeviceRevoked {
        user: sender.to_string(),
        device_key,
        timestamp,
    })
}

fn parse_anchor_state(args: &[&str], timestamp: u64) -> Option<ScEvent> {
    // anchorState(block_height: u64, state_root: hex64, message_count: u64,
    //             channel_count: u32, user_count: u32, node_id: String)
    if args.len() < 6 {
        return None;
    }
    Some(ScEvent::StateAnchored {
        block_height: decode_hex_u64(args[0])?,
        state_root: decode_hex_string(args[1])?,
        message_count: decode_hex_u64(args[2])?,
        channel_count: u32::try_from(decode_hex_u64(args[3])?).ok()?,
        user_count: u32::try_from(decode_hex_u64(args[4])?).ok()?,
        node_id: decode_hex_string(args[5])?,
        timestamp,
    })
}

fn parse_tip(args: &[&str], sender: &str, timestamp: u64) -> Option<ScEvent> {
    // tip(recipient: Address, msg_id: String, channel_id: u64, note: String)
    if args.len() < 4 {
        return None;
    }
    Some(ScEvent::TipSent {
        sender: sender.to_string(),
        recipient: decode_hex_address(args[0])?,
        amount: 0, // Amount comes from the KLV payment, not an argument
        msg_id: decode_hex_string(args[1])?,
        channel_id: decode_hex_u64(args[2])?,
        note: decode_hex_string(args[3]).unwrap_or_default(),
        timestamp,
    })
}

// --- Decoding helpers ---
// SC call arguments in the data field are hex-encoded.

/// Decode a hex-encoded UTF-8 string argument.
fn decode_hex_string(hex_arg: &str) -> Option<String> {
    let bytes = hex::decode(hex_arg).ok()?;
    String::from_utf8(bytes).ok()
}

/// Decode a hex-encoded u64 (big-endian, variable length).
fn decode_hex_u64(hex_arg: &str) -> Option<u64> {
    if hex_arg.is_empty() {
        return Some(0);
    }
    let bytes = hex::decode(hex_arg).ok()?;
    if bytes.len() > 8 {
        return None;
    }
    let mut padded = [0u8; 8];
    padded[8 - bytes.len()..].copy_from_slice(&bytes);
    Some(u64::from_be_bytes(padded))
}

/// Decode a hex-encoded u8.
fn decode_hex_u8(hex_arg: &str) -> Option<u8> {
    let v = decode_hex_u64(hex_arg)?;
    u8::try_from(v).ok()
}

/// Decode a hex-encoded Klever address (32-byte public key → bech32 klv1...).
fn decode_hex_address(hex_arg: &str) -> Option<String> {
    let bytes = hex::decode(hex_arg).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let hrp = bech32::Hrp::parse("klv").ok()?;
    bech32::encode::<bech32::Bech32>(hrp, &bytes).ok()
}
