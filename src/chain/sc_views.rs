//! Klever SC view-call clients for the v0.3.0+ Ogmara KApp surface.
//!
//! These are read-only `/vm/hex` queries against the Ogmara KApp. They
//! complement [`anchor_verify`](crate::chain::anchor_verify), which has
//! a narrower snapshot-bootstrap focus, by exposing the new
//! permissionless-registration + quorum-anchor view surface introduced
//! in spec 12.
//!
//! Encoding rules (see feedback memory "Klever SC Call Data Encoding
//! Patterns"): integer args are minimal big-endian even-length hex;
//! address args are 32 raw bytes hex-encoded; the SC's
//! `ManagedBuffer` returns are wire-encoded as raw bytes (NOT
//! hex-of-hex) — be careful, this is opposite to call-arg encoding.
//!
//! Each function gracefully treats `Anchor not found` / `Not registered`
//! style `require!` failures as `Ok(None)` / `Ok(false)`. Real
//! transport / decoding errors propagate as `Err`.

use anyhow::{Context, Result};

/// Minimal big-endian even-length hex encoding of a u64. Mirrors
/// `chain::anchor_verify::encode_u64_minimal_hex` and the anchor TX
/// builder so all SC call paths produce identical wire bytes for the
/// same value. `0` → `"00"`, `1` → `"01"`, `256` → `"0100"`.
fn encode_u64_minimal_hex(v: u64) -> String {
    if v == 0 {
        return "00".to_string();
    }
    let trimmed = format!("{:016x}", v).trim_start_matches('0').to_string();
    if trimmed.len() % 2 != 0 {
        format!("0{}", trimmed)
    } else {
        trimmed
    }
}

/// Hex-encode a klv1... address as the 32-byte raw public key the VM
/// expects on the wire. Returns `None` if the address fails bech32
/// decoding (caller should treat that as a programmer bug — wallet
/// addresses entering this module should already have been validated).
fn encode_address_hex(klv_address: &str) -> Option<String> {
    let key = crate::crypto::address_to_verifying_key(klv_address).ok()?;
    Some(hex::encode(key.as_bytes()))
}

/// Run a single `/vm/hex` query with the standard Klever JSON shape
/// and return the raw hex payload (or empty string on no-data).
async fn vm_hex_call(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    func_name: &str,
    args: &[String],
) -> Result<VmHexResponse> {
    let url = format!("{}/vm/hex", klever_node_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "scAddress": contract_address,
        "funcName": func_name,
        "args": args,
    });
    let resp: serde_json::Value = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST /vm/hex for {}", func_name))?
        .json()
        .await
        .with_context(|| format!("decoding /vm/hex response for {}", func_name))?;

    let error = resp
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let data = resp
        .pointer("/data/data")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(VmHexResponse { error, data })
}

/// Internal: separate the require!-failure case from real transport
/// errors so each caller can decide whether the failure is benign.
struct VmHexResponse {
    error: String,
    data: String,
}

impl VmHexResponse {
    /// True if the SC returned a `require!`-style failure rather than
    /// a transport / decoding error. Used to map known SC errors to
    /// `Ok(None)` / `Ok(false)` at the caller.
    fn is_require_failure(&self) -> bool {
        !self.error.is_empty()
    }
}

// ── Node registry views ─────────────────────────────────────────────

/// Returns true if the address is authorized to anchor (either via the
/// v0.3+ permissionless registry OR the legacy `authorized_anchorer`
/// allowlist during the deprecation window). Mirrors the SC's
/// `isNodeRegistered` view exactly.
///
/// Returns `Ok(false)` for any address not in either source. Returns
/// `Err` only on transport / decoding failure (the caller should retry).
pub async fn is_node_registered(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    klv_address: &str,
) -> Result<bool> {
    let address_hex = encode_address_hex(klv_address)
        .with_context(|| format!("invalid klv address: {}", klv_address))?;
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        "isNodeRegistered",
        &[address_hex],
    )
    .await?;

    if resp.is_require_failure() {
        // Bool views shouldn't `require!` — treat as "not registered".
        return Ok(false);
    }
    // bool encoding: empty payload = false, "01" = true.
    Ok(matches!(resp.data.as_str(), "01"))
}

/// Returns the count of v0.3+ registered nodes. Excludes the legacy
/// `authorized_anchorer` allowlist by design (matches the SC view).
pub async fn get_node_count(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
) -> Result<u64> {
    let resp = vm_hex_call(http, klever_node_url, contract_address, "getNodeCount", &[]).await?;
    if resp.is_require_failure() {
        return Ok(0);
    }
    Ok(decode_u64_be(&resp.data))
}

/// Returns the registration fee in raw KLV units (1 KLV = 10^6).
/// Returns `Ok(0)` if the SC fee storage is empty (registration is free).
pub async fn get_node_registration_fee(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
) -> Result<u128> {
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        "getNodeRegistrationFee",
        &[],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(0);
    }
    Ok(decode_u128_be(&resp.data))
}

/// Returns the unix-second timestamp at which `address` registered as
/// a node, or `0` if not registered (or registered via legacy allowlist
/// which doesn't track a timestamp).
pub async fn get_node_registered_at(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    klv_address: &str,
) -> Result<u64> {
    let address_hex = encode_address_hex(klv_address)
        .with_context(|| format!("invalid klv address: {}", klv_address))?;
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        "getNodeRegisteredAt",
        &[address_hex],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(0);
    }
    Ok(decode_u64_be(&resp.data))
}

// ── Quorum-verified anchor views ────────────────────────────────────

/// Returns the canonical (quorum-confirmed) state root at `block_height`,
/// or `None` if the height has not yet reached quorum (regardless of
/// whether legacy anchors exist there).
///
/// Use `chain::anchor_verify::query_klever_state_root_at` instead if you
/// need pre-v0.3 fallback behavior — that one consults the legacy
/// `getStateRoot` shim which also returns canonical for post-upgrade
/// heights.
pub async fn get_canonical_anchor(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    block_height: u64,
) -> Result<Option<String>> {
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        "getCanonicalAnchor",
        &[encode_u64_minimal_hex(block_height)],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(None);
    }
    if resp.data.is_empty() {
        return Ok(None);
    }
    // ManagedBuffer return: the SC stores the 64-char ASCII hex root.
    // The /vm/hex layer hex-encodes those ASCII bytes for transport,
    // so we hex-decode once to recover the 64-char hex string.
    let ascii =
        hex::decode(&resp.data).context("hex-decoding getCanonicalAnchor data payload")?;
    let state_root = String::from_utf8(ascii)
        .context("getCanonicalAnchor payload is not valid UTF-8")?;
    if state_root.len() != 64 {
        anyhow::bail!(
            "getCanonicalAnchor returned unexpected length: got {}, expected 64",
            state_root.len()
        );
    }
    Ok(Some(state_root))
}

/// Returns the highest block height that has reached canonical
/// (quorum) status. Zero if none yet.
pub async fn get_latest_canonical_height(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
) -> Result<u64> {
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        "getLatestCanonicalHeight",
        &[],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(0);
    }
    Ok(decode_u64_be(&resp.data))
}

// ── Decoding helpers ────────────────────────────────────────────────

/// Klever VM returns integers as big-endian minimal-length hex bytes
/// (empty payload = 0). Decode safely; bad hex defaults to 0 so a
/// transient decoding glitch surfaces as "no data" instead of
/// panicking the caller.
fn decode_u64_be(hex_data: &str) -> u64 {
    if hex_data.is_empty() {
        return 0;
    }
    let bytes = match hex::decode(hex_data) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    if bytes.len() > 8 {
        return 0;
    }
    let mut padded = [0u8; 8];
    padded[8 - bytes.len()..].copy_from_slice(&bytes);
    u64::from_be_bytes(padded)
}

/// Same as `decode_u64_be` but for 16-byte (BigUint up to 2^128) values.
/// Used for KLV amounts (raw on-chain units fit easily in u128).
fn decode_u128_be(hex_data: &str) -> u128 {
    if hex_data.is_empty() {
        return 0;
    }
    let bytes = match hex::decode(hex_data) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    if bytes.len() > 16 {
        return 0;
    }
    let mut padded = [0u8; 16];
    padded[16 - bytes.len()..].copy_from_slice(&bytes);
    u128::from_be_bytes(padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_decode_minimal() {
        assert_eq!(decode_u64_be(""), 0);
        assert_eq!(decode_u64_be("00"), 0);
        assert_eq!(decode_u64_be("01"), 1);
        assert_eq!(decode_u64_be("64"), 100);
        assert_eq!(decode_u64_be("0100"), 256);
        assert_eq!(decode_u64_be("ff"), 0xff);
        assert_eq!(decode_u64_be("ffffffffffffffff"), u64::MAX);
        // Bad hex / oversize → safe-default zero.
        assert_eq!(decode_u64_be("zz"), 0);
        assert_eq!(decode_u64_be("00112233445566778899"), 0); // 10 bytes, > u64
    }

    #[test]
    fn u128_decode_handles_klv_fee() {
        // 100 KLV in raw units = 100 * 10^6 = 100_000_000 = 0x05F5E100
        assert_eq!(decode_u128_be("05f5e100"), 100_000_000u128);
        assert_eq!(decode_u128_be(""), 0);
        // Oversize → safe-default zero.
        assert_eq!(decode_u128_be(&"01".repeat(20)), 0);
    }

    #[test]
    fn u64_encode_round_trips_with_decoder() {
        for v in [0u64, 1, 100, 256, 0xff, 0xffff, u64::MAX] {
            let encoded = encode_u64_minimal_hex(v);
            assert_eq!(decode_u64_be(&encoded), v, "round-trip for {}", v);
        }
    }
}
