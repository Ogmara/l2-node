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

/// Like `vm_hex_call` but for views returning `MultiValueEncoded<...>`.
///
/// Klever VM returns sequences as `data.data` = array-of-hex-strings,
/// one entry per encoded value. For `MultiValueEncoded<MultiValue2<A, B>>`
/// the SC flattens to `[a0, b0, a1, b1, ...]` so callers must consume
/// in pairs (or triplets, etc.) per their expected tuple shape.
async fn vm_hex_call_multi(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    func_name: &str,
    args: &[String],
) -> Result<VmHexMultiResponse> {
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
    // For multi-value returns, `data.data` is an array of hex strings.
    // Klever VM emits an empty array (or missing field) for an empty
    // result; treat both as Vec::new().
    let items = resp
        .pointer("/data/data")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok(VmHexMultiResponse { error, items })
}

struct VmHexMultiResponse {
    error: String,
    items: Vec<String>,
}

impl VmHexMultiResponse {
    fn is_require_failure(&self) -> bool {
        !self.error.is_empty()
    }
}

// ── Node registry views ─────────────────────────────────────────────

/// Returns true if the address is registered to anchor. Mirrors the
/// SC's `isNodeRegistered` view exactly — with SC ≥ 0.4.0 this is the
/// `registered_node` map only (the v0.3.x dual-OR with the legacy
/// `authorized_anchorer` allowlist was removed in spec 12 Phase 2).
///
/// Returns `Ok(false)` for any address not in the registry. Returns
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

/// Returns the count of permissionlessly-registered nodes. Equivalent
/// to `node_count` on the SC. (With SC ≥ 0.4.0 the legacy allowlist
/// is gone; this view is the only meaningful node-cardinality answer.)
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

// ── Hybrid quorum / divergence views (SC v0.4.0, spec 12 §2.8) ──────

/// Returns true if the SC has entered escalated mode for this height
/// (a second distinct root reached `ANCHOR_QUORUM_MIN`). Consumed by
/// the divergence-watcher in `chain::anchoring` to downgrade
/// `anchor_divergence` alerts from critical to info when our root
/// matches the escalated canonical (spec 12 §5.4).
pub async fn is_divergence_escalated(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    block_height: u64,
) -> Result<bool> {
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        "isDivergenceEscalated",
        &[encode_u64_minimal_hex(block_height)],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(false);
    }
    Ok(matches!(resp.data.as_str(), "01"))
}

/// Returns the snapshotted escalated quorum threshold for this height
/// (`max(ANCHOR_QUORUM_MIN + 1, node_count/2 + 1)`). Returns 0 if the
/// height never escalated. Useful for diagnostic display.
pub async fn get_escalated_threshold(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    block_height: u64,
) -> Result<u32> {
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        "getEscalatedThreshold",
        &[encode_u64_minimal_hex(block_height)],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(0);
    }
    // Threshold fits in u32 by construction (node_count is u64 but
    // realistic networks stay well under u32::MAX / 2).
    Ok(decode_u64_be(&resp.data) as u32)
}

// ── Node pause / metadata views (SC v0.4.0, spec 12 §2.10 + §2.11) ──

/// Returns true if the address is registered AND currently paused
/// (false for active OR unregistered addresses — callers needing to
/// distinguish should pair with `is_node_registered`).
pub async fn is_node_paused(
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
        "isNodePaused",
        &[address_hex],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(false);
    }
    Ok(matches!(resp.data.as_str(), "01"))
}

/// Returns the `block_timestamp` of the address's most recent
/// successful `anchorState` call (unix seconds), or 0 if they have
/// never anchored. Drives client-side staleness filtering (spec 13 §7
/// — default cutoff 7 days).
pub async fn get_node_last_anchor_at(
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
        "getNodeLastAnchorAt",
        &[address_hex],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(0);
    }
    Ok(decode_u64_be(&resp.data))
}

/// Returns the published multiaddr list for `address`. Empty result
/// means the operator has not published (the registration may still
/// be active; this view answers `getNodeMetadata`, not "is registered").
///
/// Each entry is the raw multiaddr string the operator submitted —
/// caller parses (typically with libp2p::Multiaddr::from_str). The SC
/// stores them opaquely so transport additions (QUIC variants,
/// WebTransport, onion) ship without contract upgrades.
pub async fn get_node_metadata(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    klv_address: &str,
) -> Result<Vec<String>> {
    /// Consumer-side cap on `getNodeMetadata` returned entries —
    /// defense in depth against a future SC change or a hostile RPC
    /// returning oversized payloads. The SC enforces 8 entries
    /// server-side (spec 12 §2.10 `NODE_METADATA_MAX_ENTRIES`); we
    /// allow 2× headroom and reject larger as a protocol error.
    const MAX_RETURNED_ENTRIES: usize = 16;

    let address_hex = encode_address_hex(klv_address)
        .with_context(|| format!("invalid klv address: {}", klv_address))?;
    let resp = vm_hex_call_multi(
        http,
        klever_node_url,
        contract_address,
        "getNodeMetadata",
        &[address_hex],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(Vec::new());
    }
    if resp.items.len() > MAX_RETURNED_ENTRIES {
        anyhow::bail!(
            "getNodeMetadata returned too many entries: {} > {}",
            resp.items.len(),
            MAX_RETURNED_ENTRIES
        );
    }
    // ManagedBuffer items are wire-encoded as raw bytes (hex on the
    // wire). The SC stores multiaddr strings as ASCII bytes, so each
    // hex-decoded item is the multiaddr string.
    let mut out = Vec::with_capacity(resp.items.len());
    for hex_item in &resp.items {
        let bytes = hex::decode(hex_item)
            .context("hex-decoding getNodeMetadata entry")?;
        let s = String::from_utf8(bytes)
            .context("getNodeMetadata entry is not valid UTF-8")?;
        out.push(s);
    }
    Ok(out)
}

/// One entry from `get_active_nodes` — a registered, non-paused node
/// with its last-anchor timestamp (unix seconds, 0 if never anchored).
#[derive(Debug, Clone)]
pub struct ActiveNode {
    /// The anchorer's klv1... address (bech32-encoded from on-chain
    /// 32-byte raw key).
    pub address: String,
    /// `block_timestamp` of the address's most recent successful
    /// `anchorState`. Zero if they have never anchored.
    pub last_anchor_at: u64,
}

/// Returns a paginated list of active nodes (registered + not paused)
/// from the SC. `limit` is hard-capped at 64 by the SC; passing > 64
/// will trigger a `require!` failure (treated as empty result here).
///
/// Drives `network::sc_discovery` cold-start bootstrap (spec 13 §4.3)
/// and the `bootstrap-candidates` REST endpoint.
pub async fn get_active_nodes(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    offset: u32,
    limit: u32,
) -> Result<Vec<ActiveNode>> {
    let resp = vm_hex_call_multi(
        http,
        klever_node_url,
        contract_address,
        "getActiveNodes",
        &[
            encode_u64_minimal_hex(offset as u64),
            encode_u64_minimal_hex(limit as u64),
        ],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(Vec::new());
    }

    // Layout: `MultiValueEncoded<MultiValue2<Address, u64>>` flattens
    // to [addr0_hex, ts0_hex, addr1_hex, ts1_hex, ...]. Consume in
    // pairs; an odd-length response is a protocol mismatch and we
    // surface it as an error rather than silently truncating.
    if resp.items.len() % 2 != 0 {
        anyhow::bail!(
            "getActiveNodes returned odd-length sequence: {} items",
            resp.items.len()
        );
    }

    let mut out = Vec::with_capacity(resp.items.len() / 2);
    for pair in resp.items.chunks_exact(2) {
        let addr_bytes = hex::decode(&pair[0])
            .context("hex-decoding getActiveNodes address")?;
        if addr_bytes.len() != 32 {
            anyhow::bail!(
                "getActiveNodes address has wrong length: got {}, expected 32",
                addr_bytes.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&addr_bytes);
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key)
            .context("decoding getActiveNodes Ed25519 pubkey from raw bytes")?;
        let address = crate::crypto::pubkey_to_address(&verifying_key)
            .context("encoding getActiveNodes address as bech32")?;
        let last_anchor_at = decode_u64_be(&pair[1]);
        out.push(ActiveNode {
            address,
            last_anchor_at,
        });
    }
    Ok(out)
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
