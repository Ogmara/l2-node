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
/// **Endpoint:** `/vm/query` (NOT `/vm/hex`). Discovered during the
/// SC v0.4.0 testnet bake-in: Klever's `/vm/hex` truncates multi-value
/// returns to the first emitted ManagedBuffer (it's only correct for
/// scalar single-value returns). `/vm/query` is the proper RPC for
/// arrays of return values.
///
/// **Response shape:** items live at `.data.data.returnData` as an
/// array of base64-encoded byte strings. Empty strings encode zero-
/// length values (e.g., a u64 of 0 has minimal-BE encoding `[]`).
/// For `MultiValueEncoded<MultiValue2<A, B>>` the SC flattens to
/// `[a0_b64, b0_b64, a1_b64, b1_b64, ...]` so callers consume in pairs
/// (or triplets, etc.) per their expected tuple shape.
///
/// **Error handling:** transport errors propagate as `Err`. SC-level
/// `require!` failures show up as a non-Ok `returnCode` in the inner
/// response — surfaced via the `error` field on the returned struct
/// so callers can map them to `Ok(empty)` like before.
async fn vm_query_multi(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    func_name: &str,
    args: &[String],
) -> Result<VmQueryMultiResponse> {
    let url = format!("{}/vm/query", klever_node_url.trim_end_matches('/'));
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
        .with_context(|| format!("POST /vm/query for {}", func_name))?
        .json()
        .await
        .with_context(|| format!("decoding /vm/query response for {}", func_name))?;

    // Two sources of error:
    //   1. Top-level `.error` (transport / endpoint failure)
    //   2. Inner `.data.data.returnCode` (SC require! / VMUserError)
    let top_error = resp
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let return_code = resp
        .pointer("/data/data/returnCode")
        .and_then(|v| v.as_str())
        .unwrap_or("Ok")
        .to_string();
    let return_message = resp
        .pointer("/data/data/returnMessage")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let error = if !top_error.is_empty() {
        top_error
    } else if return_code != "Ok" {
        // Surface the SC's returnMessage (e.g., "Not registered") so
        // callers can map known failures to benign `Ok(empty)`.
        if return_message.is_empty() {
            return_code
        } else {
            return_message
        }
    } else {
        String::new()
    };

    // Decode returnData (array of base64 strings) into raw byte vectors.
    // Empty string → empty Vec<u8> (legitimate for zero-value encodings).
    let items_b64: Vec<&str> = resp
        .pointer("/data/data/returnData")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    use base64::Engine;
    let b64_engine = base64::engine::general_purpose::STANDARD;
    let mut items: Vec<Vec<u8>> = Vec::with_capacity(items_b64.len());
    for b64 in items_b64 {
        let bytes = if b64.is_empty() {
            Vec::new()
        } else {
            b64_engine
                .decode(b64)
                .with_context(|| format!("base64-decoding {} returnData entry", func_name))?
        };
        items.push(bytes);
    }

    Ok(VmQueryMultiResponse { error, items })
}

struct VmQueryMultiResponse {
    error: String,
    /// Raw bytes for each return value, in order. Empty Vec = zero-
    /// length encoding (e.g., u64 of 0).
    items: Vec<Vec<u8>>,
}

impl VmQueryMultiResponse {
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

/// Returns the number of registered nodes that are NOT paused (SC 0.5.0+).
/// This — not [`get_node_count`] — is the denominator behind the hybrid
/// quorum escalation threshold (`max(4, active/2 + 1)`, spec 12 §2.8): a
/// paused node cannot anchor, so it does not count toward how many
/// agreeing anchorers a contested height needs. Surfaced separately from
/// `network_node_count` in the dashboard so "registered" and "active"
/// don't get conflated when some nodes are paused.
pub async fn get_active_node_count(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
) -> Result<u64> {
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        "getActiveNodeCount",
        &[],
    )
    .await?;
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

/// Returns the USER registration fee in raw KLV units (1 KLV = 10^6).
///
/// `Ok(0)` means registration is currently free — which is the state of an
/// already-deployed contract until its owner switches the fee on, so it is
/// the expected reading, not an error. Clients MUST read this before
/// building a `register` transaction: the fee is node-governance controlled
/// and changes without any client release.
///
/// Added in SC 0.10.0. An older contract has no such endpoint, so the call
/// fails `require` and this returns `Ok(0)` — the same value as "free",
/// which is the correct fallback in both cases.
pub async fn get_registration_fee(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
) -> Result<u128> {
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        "getRegistrationFee",
        &[],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(0);
    }
    Ok(decode_u128_be(&resp.data))
}

/// Returns the share of each user registration fee routed to the referring
/// node, in basis points (10_000 = 100%). `Ok(0)` = the whole fee goes to
/// the protocol treasury. Added in SC 0.10.0; capped on-chain at 8000.
pub async fn get_node_fee_share_bps(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
) -> Result<u64> {
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        "getNodeFeeShareBps",
        &[],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(0);
    }
    Ok(decode_u64_be(&resp.data))
}

/// Returns the unclaimed KLV `klv_address` has accrued from users who
/// registered through its node. Claimed with the `claimNodeEarnings`
/// endpoint. `Ok(0)` for a non-node address or one with nothing owed.
///
/// Decoded as `u128`, not `u64`: this accumulates without bound until
/// claimed, so it must not silently truncate.
pub async fn get_node_earnings(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    klv_address: &str,
) -> Result<u128> {
    let address_hex = encode_address_hex(klv_address)
        .with_context(|| format!("invalid klv address: {}", klv_address))?;
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        "getNodeEarnings",
        &[address_hex],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(0);
    }
    Ok(decode_u128_be(&resp.data))
}

/// Returns the total unclaimed node earnings across every operator — the
/// contract's outstanding liability to node operators. Added in SC 0.10.0.
pub async fn get_total_unclaimed_node_earnings(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
) -> Result<u128> {
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        "getTotalUnclaimedNodeEarnings",
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

/// Returns the MATERIALIZED escalated-mode resolution for a height, or
/// `None` if it has not (yet) been written on-chain.
///
/// Distinct from [`get_canonical_anchor`]: for an escalated height,
/// `get_canonical_anchor` returns the §2.9 tiebreak's PROVISIONAL preview
/// (computed read-only) the instant escalation triggers — well before the
/// `TIEBREAK_GRACE_PERIOD_SECS` window closes, and that preview can still
/// be overridden by genuine escalated-quorum agreement on a DIFFERENT root
/// during the window. This function raw-reads `escalated_canonical` with
/// no fallback computation, so `None` here means "still provisional,"
/// never "not escalated" — check `is_divergence_escalated` first. Once
/// `Some`, the value is final (write-once on-chain) and always matches
/// what `get_canonical_anchor` returns for that height from then on.
///
/// Added in SC 0.7.0 specifically so the divergence-watcher (below) can
/// avoid treating a provisional preview as a settled resolution.
pub async fn get_escalated_canonical(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    block_height: u64,
) -> Result<Option<String>> {
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        "getEscalatedCanonical",
        &[encode_u64_minimal_hex(block_height)],
    )
    .await?;
    if resp.is_require_failure() || resp.data.is_empty() {
        return Ok(None);
    }
    let ascii =
        hex::decode(&resp.data).context("hex-decoding getEscalatedCanonical data payload")?;
    let state_root = String::from_utf8(ascii)
        .context("getEscalatedCanonical payload is not valid UTF-8")?;
    if state_root.len() != 64 {
        anyhow::bail!(
            "getEscalatedCanonical returned unexpected length: got {}, expected 64",
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
    let resp = vm_query_multi(
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
    // Each item is raw bytes of a ManagedBuffer. The SC stores
    // multiaddr strings as ASCII bytes, so each item IS the multiaddr
    // string in bytes.
    let mut out = Vec::with_capacity(resp.items.len());
    for bytes in resp.items {
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
    let resp = vm_query_multi(
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
    // to [addr0_bytes, ts0_bytes, addr1_bytes, ts1_bytes, ...]. Each
    // address is 32 raw bytes; each u64 is minimal-BE bytes (possibly
    // empty for zero). Consume in pairs; an odd-length response is a
    // protocol mismatch and we surface it as an error.
    if resp.items.len() % 2 != 0 {
        anyhow::bail!(
            "getActiveNodes returned odd-length sequence: {} items",
            resp.items.len()
        );
    }

    let mut out = Vec::with_capacity(resp.items.len() / 2);
    for pair in resp.items.chunks_exact(2) {
        let addr_bytes = &pair[0];
        if addr_bytes.len() != 32 {
            anyhow::bail!(
                "getActiveNodes address has wrong length: got {}, expected 32",
                addr_bytes.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(addr_bytes);
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key)
            .context("decoding getActiveNodes Ed25519 pubkey from raw bytes")?;
        let address = crate::crypto::pubkey_to_address(&verifying_key)
            .context("encoding getActiveNodes address as bech32")?;
        let last_anchor_at = decode_u64_be_bytes(&pair[1]);
        out.push(ActiveNode {
            address,
            last_anchor_at,
        });
    }
    Ok(out)
}

// ── Governance views (governance-dashboard-plan.md Phase 5) ─────────
//
// Two independent tracks on the SC (user-gated `listProposals`/
// `getProposalTally`/`getUserVote`/`getProposalCount`, and the additive
// node-gated `listNodeProposals`/`getNodeProposalTally`/`getNodeVote`/
// `getNodeProposalCount`) share byte-identical wire shapes — same
// 13-field list-item layout, same 5-field tally, same single-`u8` vote
// status. DRY design: one private generic decode+fetch helper per
// shape, `func_name` is the only thing that differs between the two
// tracks' thin public wrappers below. This halves the decode-logic
// surface area that could drift or have an undetected bug in one track
// but not the other. `get_node_count`/`get_active_node_count` (above)
// are the node-track quorum denominator and need no new code here.

/// One row from `listProposals`/`listNodeProposals` — the flattened
/// 13-field `MultiValue13` tuple the SC's `query.rs` emits for both
/// tracks (id, proposer, description, param_key, param_value,
/// created_at, expires_at, executed, vote_count, oppose_count, quorum,
/// quorum_met, supermajority_met).
#[derive(Debug, Clone)]
pub struct ProposalSummary {
    pub id: u64,
    /// bech32 klv1... address, decoded via the same raw-bytes →
    /// `VerifyingKey` → `pubkey_to_address` path `get_active_nodes` uses.
    pub proposer: String,
    /// Attacker-influenced: any registered user/node can set this
    /// (up to 512 bytes, SC-enforced) via `createProposal`/
    /// `createNodeProposal`. Not sanitized at this layer by design —
    /// escape/sanitize at the render layer (dashboard, Phase 7), not here.
    pub description: String,
    /// Attacker-influenced — see `description`. Not sanitized here.
    pub param_key: String,
    /// Decimal string — the on-chain value is a `BigUint` which may
    /// exceed u64/u128, so this is never parsed into a fixed-width
    /// integer here. Phase 6's calldata builder will need the reverse
    /// (decimal string → bytes) conversion; share `bytes_be_to_decimal_string`
    /// with it rather than writing a second, untested one.
    pub param_value: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub executed: bool,
    pub vote_count: u64,
    pub oppose_count: u64,
    pub quorum: u64,
    pub quorum_met: bool,
    pub supermajority_met: bool,
}

/// The `MultiValue5<u64, u64, u64, bool, bool>` tally shape shared by
/// `getProposalTally`/`getNodeProposalTally` — also exactly the trailing
/// 5 fields of [`ProposalSummary`].
#[derive(Debug, Clone)]
pub struct ProposalTally {
    pub vote_count: u64,
    pub oppose_count: u64,
    pub quorum: u64,
    pub quorum_met: bool,
    pub supermajority_met: bool,
}

/// Flattened return-item count per proposal row — the 13-field tuple
/// both tracks' `listX` views share.
const PROPOSAL_SUMMARY_ITEM_COUNT: usize = 13;

/// Consumer-side cap on `listProposals`/`listNodeProposals` returned
/// items — defense in depth against a future SC change or a
/// hostile/compromised RPC endpoint returning an oversized payload,
/// same rationale as `get_node_metadata`'s `MAX_RETURNED_ENTRIES`
/// above. The SC enforces `limit <= LIST_PROPOSALS_MAX_LIMIT` (20)
/// server-side (`smart-contract/src/governance.rs`); this allows 2x
/// headroom (40 rows) and rejects larger as a protocol error, BEFORE
/// building any `ProposalSummary` — `vm_query_multi` itself has no
/// size bound, so without this check a malicious `klever_node_url`
/// could force unbounded base64-decode + allocation here.
const MAX_RETURNED_PROPOSAL_ROWS: usize = 40;

/// klever-sc bool wire encoding on a `/vm/query` multi-value item: empty
/// = false, non-empty (first byte nonzero) = true. This is the
/// multi-value counterpart to the `/vm/hex` scalar-bool convention
/// `is_node_registered`/`is_node_paused` already rely on (`"01"` = true,
/// empty = false).
fn decode_bool_bytes(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes[0] != 0
}

/// 32 raw bytes → bech32 klv1... address. Same two calls
/// `get_active_nodes` already makes inline (kept as a named helper here
/// since a governance list response decodes a proposer address in
/// EVERY row of a page, not just once per call).
fn decode_address_bytes(func_name: &str, bytes: &[u8]) -> Result<String> {
    if bytes.len() != 32 {
        anyhow::bail!(
            "{} address has wrong length: got {}, expected 32",
            func_name,
            bytes.len()
        );
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key)
        .with_context(|| format!("decoding {} Ed25519 pubkey from raw bytes", func_name))?;
    crate::crypto::pubkey_to_address(&verifying_key)
        .with_context(|| format!("encoding {} address as bech32", func_name))
}

/// Decode one flattened proposal-summary chunk (exactly
/// [`PROPOSAL_SUMMARY_ITEM_COUNT`] items) into a [`ProposalSummary`].
/// `func_name` is only used to make error messages point at the right
/// caller — the decode logic itself is track-agnostic.
fn decode_proposal_summary(func_name: &str, items: &[Vec<u8>]) -> Result<ProposalSummary> {
    if items.len() != PROPOSAL_SUMMARY_ITEM_COUNT {
        anyhow::bail!(
            "{} returned unexpected item count in one row: {} (expected {})",
            func_name,
            items.len(),
            PROPOSAL_SUMMARY_ITEM_COUNT
        );
    }
    Ok(ProposalSummary {
        id: decode_u64_be_bytes(&items[0]),
        proposer: decode_address_bytes(func_name, &items[1])?,
        description: String::from_utf8(items[2].clone())
            .with_context(|| format!("{} description is not valid UTF-8", func_name))?,
        param_key: String::from_utf8(items[3].clone())
            .with_context(|| format!("{} param_key is not valid UTF-8", func_name))?,
        param_value: bytes_be_to_decimal_string(&items[4]),
        created_at: decode_u64_be_bytes(&items[5]),
        expires_at: decode_u64_be_bytes(&items[6]),
        executed: decode_bool_bytes(&items[7]),
        vote_count: decode_u64_be_bytes(&items[8]),
        oppose_count: decode_u64_be_bytes(&items[9]),
        quorum: decode_u64_be_bytes(&items[10]),
        quorum_met: decode_bool_bytes(&items[11]),
        supermajority_met: decode_bool_bytes(&items[12]),
    })
}

/// Decode a 5-item `MultiValue5<u64, u64, u64, bool, bool>` tally.
fn decode_proposal_tally(func_name: &str, items: &[Vec<u8>]) -> Result<ProposalTally> {
    if items.len() != 5 {
        anyhow::bail!(
            "{} returned unexpected item count: {} (expected 5)",
            func_name,
            items.len()
        );
    }
    Ok(ProposalTally {
        vote_count: decode_u64_be_bytes(&items[0]),
        oppose_count: decode_u64_be_bytes(&items[1]),
        quorum: decode_u64_be_bytes(&items[2]),
        quorum_met: decode_bool_bytes(&items[3]),
        supermajority_met: decode_bool_bytes(&items[4]),
    })
}

/// Shared paginated-list fetch+decode. `func_name` is the only thing
/// that differs between `listProposals` (user track) and
/// `listNodeProposals` (node track).
async fn list_proposals_generic(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    func_name: &str,
    offset: u32,
    limit: u32,
) -> Result<Vec<ProposalSummary>> {
    let resp = vm_query_multi(
        http,
        klever_node_url,
        contract_address,
        func_name,
        &[
            encode_u64_minimal_hex(offset as u64),
            encode_u64_minimal_hex(limit as u64),
        ],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(Vec::new());
    }
    if resp.items.len() > MAX_RETURNED_PROPOSAL_ROWS * PROPOSAL_SUMMARY_ITEM_COUNT {
        anyhow::bail!(
            "{} returned too many items: {} > {} rows worth ({})",
            func_name,
            resp.items.len(),
            MAX_RETURNED_PROPOSAL_ROWS,
            MAX_RETURNED_PROPOSAL_ROWS * PROPOSAL_SUMMARY_ITEM_COUNT
        );
    }
    if resp.items.len() % PROPOSAL_SUMMARY_ITEM_COUNT != 0 {
        anyhow::bail!(
            "{} returned a length not a multiple of {}: {} items",
            func_name,
            PROPOSAL_SUMMARY_ITEM_COUNT,
            resp.items.len()
        );
    }
    resp.items
        .chunks_exact(PROPOSAL_SUMMARY_ITEM_COUNT)
        .map(|chunk| decode_proposal_summary(func_name, chunk))
        .collect()
}

/// Shared proposal-count fetch+decode (plain scalar u64 via `/vm/hex`,
/// same pattern as `get_node_count`).
async fn get_proposal_count_generic(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    func_name: &str,
) -> Result<u64> {
    let resp = vm_hex_call(http, klever_node_url, contract_address, func_name, &[]).await?;
    if resp.is_require_failure() {
        return Ok(0);
    }
    Ok(decode_u64_be(&resp.data))
}

/// Shared tally fetch+decode. `Ok(None)` for a nonexistent proposal ID
/// (the SC's `require!(!proposal(id).is_empty(), "Proposal not
/// found")`) — a benign, expected case, not a transport error.
async fn get_proposal_tally_generic(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    func_name: &str,
    proposal_id: u64,
) -> Result<Option<ProposalTally>> {
    let resp = vm_query_multi(
        http,
        klever_node_url,
        contract_address,
        func_name,
        &[encode_u64_minimal_hex(proposal_id)],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(None);
    }
    Ok(Some(decode_proposal_tally(func_name, &resp.items)?))
}

/// Shared vote-status fetch+decode: 0 = has not voted, 1 = support, 2 =
/// oppose — mirrors the SC's `VOTE_SUPPORT`/`VOTE_OPPOSE` u8 markers
/// (`governance.rs`), reused as-is by the node track.
async fn get_vote_status_generic(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    func_name: &str,
    proposal_id: u64,
    voter_klv_address: &str,
) -> Result<u8> {
    let address_hex = encode_address_hex(voter_klv_address)
        .with_context(|| format!("invalid klv address: {}", voter_klv_address))?;
    let resp = vm_hex_call(
        http,
        klever_node_url,
        contract_address,
        func_name,
        &[encode_u64_minimal_hex(proposal_id), address_hex],
    )
    .await?;
    if resp.is_require_failure() || resp.data.is_empty() {
        return Ok(0);
    }
    let bytes = hex::decode(&resp.data)
        .with_context(|| format!("decoding {} u8 return as hex", func_name))?;
    Ok(bytes.first().copied().unwrap_or(0))
}

// --- User-track wrappers ---

pub async fn get_proposal_count(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
) -> Result<u64> {
    get_proposal_count_generic(http, klever_node_url, contract_address, "getProposalCount").await
}

pub async fn list_proposals(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    offset: u32,
    limit: u32,
) -> Result<Vec<ProposalSummary>> {
    list_proposals_generic(
        http,
        klever_node_url,
        contract_address,
        "listProposals",
        offset,
        limit,
    )
    .await
}

pub async fn get_proposal_tally(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    proposal_id: u64,
) -> Result<Option<ProposalTally>> {
    get_proposal_tally_generic(
        http,
        klever_node_url,
        contract_address,
        "getProposalTally",
        proposal_id,
    )
    .await
}

pub async fn get_user_vote(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    proposal_id: u64,
    voter_klv_address: &str,
) -> Result<u8> {
    get_vote_status_generic(
        http,
        klever_node_url,
        contract_address,
        "getUserVote",
        proposal_id,
        voter_klv_address,
    )
    .await
}

// --- Node-track wrappers (additive) ---

pub async fn get_node_proposal_count(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
) -> Result<u64> {
    get_proposal_count_generic(
        http,
        klever_node_url,
        contract_address,
        "getNodeProposalCount",
    )
    .await
}

pub async fn list_node_proposals(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    offset: u32,
    limit: u32,
) -> Result<Vec<ProposalSummary>> {
    list_proposals_generic(
        http,
        klever_node_url,
        contract_address,
        "listNodeProposals",
        offset,
        limit,
    )
    .await
}

pub async fn get_node_proposal_tally(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    proposal_id: u64,
) -> Result<Option<ProposalTally>> {
    get_proposal_tally_generic(
        http,
        klever_node_url,
        contract_address,
        "getNodeProposalTally",
        proposal_id,
    )
    .await
}

pub async fn get_node_vote(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    proposal_id: u64,
    voter_klv_address: &str,
) -> Result<u8> {
    get_vote_status_generic(
        http,
        klever_node_url,
        contract_address,
        "getNodeVote",
        proposal_id,
        voter_klv_address,
    )
    .await
}

// ── Transport classifier (spec 13 §4.5, l2-node 0.46.5+) ────────────

/// Coarse transport tag derived from a multiaddr's protocol stack.
/// Used to surface "high-resilience mode available" in dashboards and
/// to let SDK consumers filter peer candidates by reachability profile
/// without having to parse multiaddrs themselves (spec 13 §4.5).
///
/// Classification is client-side and intentionally permissive:
/// unrecognized protocol stacks degrade to [`TransportKind::Unknown`]
/// rather than triggering an error so a forward-compat SC change
/// (new transport string published via `setNodeMetadata`) does not
/// break older nodes — they just emit `unknown` until they're upgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    /// Public-internet transport: `/ip4`, `/ip6`, `/dns4`, `/dns6`,
    /// `/dns` followed by `/tcp` or `/udp + /quic-v1`.
    Clearnet,
    /// Tor onion service: `/onion` or `/onion3`.
    Onion,
    /// I2P garlic routing: `/garlic` (reserved — no current
    /// implementation; emit if and when an operator publishes one).
    I2p,
    /// Anything else (loopback `/ip4/127.0.0.1`, future protocols,
    /// malformed payloads). Caller decides whether to dial these.
    Unknown,
}

impl TransportKind {
    /// Lowercase wire string used by REST responses and dashboards.
    /// Stable identifier — clients pin against these values, so any
    /// rename here is a breaking API change.
    pub fn as_str(self) -> &'static str {
        match self {
            TransportKind::Clearnet => "clearnet",
            TransportKind::Onion => "onion",
            TransportKind::I2p => "i2p",
            TransportKind::Unknown => "unknown",
        }
    }
}

/// Classify a multiaddr string by its outermost transport-meaningful
/// protocol prefix. Routable-clearnet detection parses the multiaddr's
/// IP component (when present) and rejects all non-routable ranges,
/// not just loopback — defense against a hostile node operator who
/// publishes a private-network or cloud-metadata multiaddr via
/// `setNodeMetadata` to trick SDK consumers into surfacing or dialing
/// internal targets (Security Audit W1, 0.46.5).
///
/// Rules (first match wins, scanned left-to-right):
/// - Contains `/onion3/` or `/onion/` → [`TransportKind::Onion`]
/// - Contains `/garlic/` → [`TransportKind::I2p`]
/// - `/ip4/<addr>/...` or `/ip6/<addr>/...` with `<addr>` in any
///   non-routable range (loopback, RFC1918, link-local + AWS/Azure
///   metadata endpoint at 169.254.169.254, ULA, unspecified,
///   broadcast, CGNAT, IPv4-mapped IPv6, multicast) →
///   [`TransportKind::Unknown`]. The dial decision still belongs to
///   libp2p; we just refuse to *advertise* internal targets as
///   "clearnet" via the discovery API.
/// - `/dns4/`, `/dns6/`, `/dns/`, or routable `/ip4|6/` host + `/tcp/`
///   or (`/udp/` + `/quic`) → [`TransportKind::Clearnet`]
/// - Anything else → [`TransportKind::Unknown`]
///
/// NOTE: `/webrtc-direct/`, `/wss/`, `/ws/` and other browser-oriented
/// transports are intentionally not yet classified as `Clearnet` —
/// they degrade to `Unknown` until a future revision adds explicit
/// handling. SDK consumers filtering on `clearnet` therefore see only
/// TCP / QUIC, which is the v0.46.5 deployment surface.
pub fn classify_transport(multiaddr_str: &str) -> TransportKind {
    // Onion check first — onion multiaddrs may also include /tcp/, but
    // they should classify as Onion regardless.
    if multiaddr_str.contains("/onion3/") || multiaddr_str.contains("/onion/") {
        return TransportKind::Onion;
    }
    if multiaddr_str.contains("/garlic/") {
        return TransportKind::I2p;
    }

    // For /ip4/ and /ip6/ multiaddrs, parse the IP literal and require
    // it to be in a publicly-routable range. Anything else (private,
    // link-local incl. metadata-endpoint 169.254.169.254, ULA,
    // loopback, multicast, unspecified, broadcast, IPv4-mapped IPv6,
    // CGNAT) classifies as Unknown rather than Clearnet (Security
    // Audit W1 0.46.5: prevents a hostile node operator from
    // publishing a private-network target as a discovery candidate
    // that dashboards / SDKs would surface as a normal-looking peer).
    let host_routable = if let Some(rest) = multiaddr_str.strip_prefix("/ip4/") {
        let lit = rest.split('/').next().unwrap_or("");
        match lit.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => ipv4_is_publicly_routable(&ip),
            Err(_) => false,
        }
    } else if let Some(rest) = multiaddr_str.strip_prefix("/ip6/") {
        let lit = rest.split('/').next().unwrap_or("");
        match lit.parse::<std::net::Ipv6Addr>() {
            Ok(ip) => ipv6_is_publicly_routable(&ip),
            Err(_) => false,
        }
    } else if multiaddr_str.starts_with("/dns4/")
        || multiaddr_str.starts_with("/dns6/")
        || multiaddr_str.starts_with("/dns/")
    {
        // DNS names: we don't resolve here (would leak to a DNS
        // provider and add latency to every classification). Treat
        // as routable for the transport tag; libp2p / the dialer is
        // still responsible for honouring SOCKS5 / refusing private
        // resolutions at dial time.
        true
    } else {
        false
    };
    let has_transport = multiaddr_str.contains("/tcp/")
        || (multiaddr_str.contains("/udp/") && multiaddr_str.contains("/quic"));
    if host_routable && has_transport {
        return TransportKind::Clearnet;
    }
    TransportKind::Unknown
}

/// True iff the IPv4 address is in a globally-routable unicast range.
/// Rejects loopback, RFC1918 private, link-local (incl. cloud
/// metadata endpoints), unspecified, broadcast, and CGNAT
/// (100.64.0.0/10). `is_unique_local` / `is_shared` are
/// nightly-only on `Ipv4Addr`, so the CGNAT check is inlined.
fn ipv4_is_publicly_routable(ip: &std::net::Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
    {
        return false;
    }
    let o = ip.octets();
    // CGNAT 100.64.0.0/10 — RFC6598. `Ipv4Addr::is_shared` is unstable.
    if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
        return false;
    }
    true
}

/// True iff the IPv6 address is in a globally-routable unicast range.
/// Rejects loopback, unspecified, ULA `fc00::/7`, link-local
/// `fe80::/10`, multicast `ff00::/8`, and IPv4-mapped `::ffff:0:0/96`.
fn ipv6_is_publicly_routable(ip: &std::net::Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    let s = ip.segments();
    // Multicast ff00::/8
    if (s[0] & 0xff00) == 0xff00 {
        return false;
    }
    // ULA fc00::/7 (`is_unique_local` is unstable).
    if (s[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // Link-local fe80::/10 (`is_unicast_link_local` is unstable).
    if (s[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // IPv4-mapped ::ffff:0:0/96 — accidentally classifying these as
    // routable IPv6 would re-introduce the IPv4 attack surface this
    // function is meant to close.
    if s[0..5].iter().all(|&x| x == 0) && s[5] == 0xffff {
        return false;
    }
    // Documentation 2001:db8::/32.
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return false;
    }
    true
}

// ── User + channel registry views (SC 0.6.1) ─────────────────────────
//
// These read on-chain records the l2-node ALREADY tracks locally (from
// `UserRegistered` / `ChannelCreate` gossip events, stored in RocksDB) —
// so they are not on the node's own hot path; the local copy is faster
// and doesn't round-trip to Klever RPC. They exist here as the on-chain
// source-of-truth reads for reconciliation / verification tooling and
// for SDK consumers who query the chain directly without running a node.

/// Registration timestamp for a registered user, or `0` if not registered.
pub async fn get_user_registered_at(
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
        "getUserRegisteredAt",
        &[address_hex],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(0);
    }
    Ok(decode_u64_be(&resp.data))
}

/// A channel's on-chain type + creation timestamp.
pub struct ChannelInfo {
    /// 0 = Public, 1 = ReadPublic.
    pub channel_type: u8,
    pub created_at: u64,
}

/// Returns a channel's type and creation timestamp, or `None` if the
/// channel does not exist on-chain.
pub async fn get_channel_info(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    channel_id: u64,
) -> Result<Option<ChannelInfo>> {
    let resp = vm_query_multi(
        http,
        klever_node_url,
        contract_address,
        "getChannelInfo",
        &[encode_u64_minimal_hex(channel_id)],
    )
    .await?;
    if resp.is_require_failure() {
        return Ok(None);
    }
    decode_channel_info(&resp.items).map(Some)
}

/// Decode the `MultiValue2<u8, u64>` payload of `getChannelInfo` into a
/// [`ChannelInfo`]. Split out from [`get_channel_info`] so the decode logic
/// is unit-testable without an HTTP round-trip (this crate has no mock-HTTP
/// harness).
fn decode_channel_info(items: &[Vec<u8>]) -> Result<ChannelInfo> {
    // MultiValue2<u8, u64> flattens to exactly 2 return items.
    if items.len() != 2 {
        anyhow::bail!(
            "getChannelInfo returned unexpected item count: {} (expected 2)",
            items.len()
        );
    }
    let channel_type = match items[0].as_slice() {
        [] => 0,
        [b] => *b,
        _ => anyhow::bail!("getChannelInfo channel_type has unexpected length"),
    };
    let created_at = decode_u64_be_bytes(&items[1]);
    Ok(ChannelInfo {
        channel_type,
        created_at,
    })
}

// ── Decoding helpers ────────────────────────────────────────────────

/// Decode a u64 from minimal big-endian raw bytes (used by
/// `vm_query_multi` consumers). Empty slice = 0. Oversize (> 8
/// bytes) → 0 (safe-default to surface protocol issues as "no data"
/// instead of panicking).
fn decode_u64_be_bytes(bytes: &[u8]) -> u64 {
    if bytes.is_empty() || bytes.len() > 8 {
        return 0;
    }
    let mut padded = [0u8; 8];
    padded[8 - bytes.len()..].copy_from_slice(bytes);
    u64::from_be_bytes(padded)
}

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

/// Arbitrary-precision big-endian bytes → decimal string. Used for
/// governance `param_value` (an on-chain `BigUint` — fees can
/// legitimately exceed u64/u128, e.g. an owner accidentally proposing a
/// huge `node_registration_fee`, so this must not silently truncate).
/// Empty bytes → `"0"`.
///
/// Hand-rolled schoolbook base-256→base-10 conversion (no `num-bigint`
/// dependency — this codebase prefers minimal deps for small,
/// self-contained utilities like this one) — repeatedly multiplies a
/// little-endian decimal-digit accumulator by 256 and adds the next
/// byte, carrying overflow into new digits. O(n²) in byte length, but n
/// is always tiny here (a handful of bytes for any realistic KLV fee).
///
/// Phase 6 (governance-dashboard-plan.md) needs the REVERSE conversion
/// (decimal string → minimal big-endian bytes, for the create-proposal
/// calldata builder) — pair a `decimal_string_to_bytes_be` with this
/// function then and share one round-trip test, rather than writing a
/// second, independently-tested big-int conversion.
fn bytes_be_to_decimal_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0".to_string();
    }
    // Little-endian decimal digits (digits[0] is the ones place).
    let mut digits: Vec<u8> = vec![0];
    for &byte in bytes {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            let v = (*d as u32) * 256 + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    while digits.len() > 1 && *digits.last().unwrap() == 0 {
        digits.pop();
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

/// Reverse of [`bytes_be_to_decimal_string`] — decimal string → minimal
/// big-endian bytes (empty for `"0"`). Used by the create-node-proposal
/// calldata builder (governance-dashboard-plan.md Phase 6, `param_value`
/// TX arg) so there is exactly one tested BigUint⇄bytes conversion in
/// this codebase, not two. Validates the input is a plain non-negative
/// decimal integer (ASCII digits only, no sign, no leading zeros other
/// than a bare `"0"`) — SC `BigUint` args are always non-negative and a
/// malformed string here should fail loudly, not silently coerce.
///
/// Schoolbook long division by 256 over the decimal-digit
/// representation (the mirror image of the multiply-accumulate in
/// `bytes_be_to_decimal_string`) — same O(n²)-in-digit-count
/// complexity, same "n is always tiny for a realistic fee" rationale.
pub(crate) fn decimal_string_to_bytes_be(s: &str) -> Result<Vec<u8>> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        anyhow::bail!("not a valid non-negative decimal integer: {:?}", s);
    }
    if s.len() > 1 && s.starts_with('0') {
        anyhow::bail!("decimal integer has a leading zero: {:?}", s);
    }
    if s == "0" {
        return Ok(Vec::new());
    }
    // Big-endian (MSB-first) decimal digits, mutated in place by
    // repeated division.
    let mut digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
    let mut out_bytes_le: Vec<u8> = Vec::new();
    while !(digits.len() == 1 && digits[0] == 0) {
        let mut remainder: u32 = 0;
        for d in digits.iter_mut() {
            let cur = remainder * 10 + (*d as u32);
            *d = (cur / 256) as u8;
            remainder = cur % 256;
        }
        out_bytes_le.push(remainder as u8);
        while digits.len() > 1 && digits[0] == 0 {
            digits.remove(0);
        }
    }
    out_bytes_le.reverse();
    Ok(out_bytes_le)
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

    // --- getChannelInfo decode (SC 0.6.1) -----------------------------

    #[test]
    fn channel_info_decodes_type_and_timestamp() {
        // channel_type=1 (ReadPublic), created_at=1_700_000_000
        // (0x6553F100 big-endian minimal bytes).
        let info = decode_channel_info(&[vec![1u8], vec![0x65, 0x53, 0xF1, 0x00]]).unwrap();
        assert_eq!(info.channel_type, 1);
        assert_eq!(info.created_at, 1_700_000_000);
    }

    #[test]
    fn channel_info_zero_values_decode_as_empty_bytes() {
        // u8(0) and u64(0) both minimal-encode to zero-length on the wire —
        // mirrors klever-sc's general zero-value convention.
        let info = decode_channel_info(&[vec![], vec![]]).unwrap();
        assert_eq!(info.channel_type, 0);
        assert_eq!(info.created_at, 0);
    }

    #[test]
    fn channel_info_rejects_wrong_item_count() {
        assert!(decode_channel_info(&[vec![1u8]]).is_err());
        assert!(decode_channel_info(&[vec![1u8], vec![0u8], vec![0u8]]).is_err());
    }

    #[test]
    fn channel_info_rejects_oversized_type_byte() {
        assert!(decode_channel_info(&[vec![1u8, 2u8], vec![]]).is_err());
    }

    // --- Transport classifier (spec 13 §4.5, 0.46.5+) ----------------

    #[test]
    fn classify_clearnet_dns_tcp() {
        assert_eq!(
            classify_transport("/dns4/example.org/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Clearnet
        );
    }

    #[test]
    fn classify_clearnet_dns_quic() {
        assert_eq!(
            classify_transport("/dns4/example.org/udp/41720/quic-v1/p2p/12D3KooW..."),
            TransportKind::Clearnet
        );
    }

    #[test]
    fn classify_clearnet_ip4_tcp() {
        // 1.1.1.1 (Cloudflare DNS) — unambiguously routable public IPv4.
        assert_eq!(
            classify_transport("/ip4/1.1.1.1/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Clearnet
        );
    }

    #[test]
    fn classify_onion3() {
        assert_eq!(
            classify_transport("/onion3/abc123/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Onion
        );
    }

    #[test]
    fn classify_onion_legacy() {
        assert_eq!(
            classify_transport("/onion/abc123/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Onion
        );
    }

    #[test]
    fn classify_garlic_is_i2p() {
        assert_eq!(
            classify_transport("/garlic/abc123/tcp/41720/p2p/12D3KooW..."),
            TransportKind::I2p
        );
    }

    #[test]
    fn classify_loopback_is_unknown() {
        // Loopback isn't useful as a cross-node bootstrap candidate.
        assert_eq!(
            classify_transport("/ip4/127.0.0.1/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Unknown
        );
        assert_eq!(
            classify_transport("/ip6/::1/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Unknown
        );
    }

    #[test]
    fn classify_rfc1918_is_unknown() {
        // Security Audit W1 (0.46.5): hostile node operators must not
        // be able to publish a private-network multiaddr that the
        // discovery API surfaces as "clearnet" and an SDK would dial.
        for raw in [
            "/ip4/10.0.0.1/tcp/41720/p2p/12D3KooW...",
            "/ip4/172.16.0.1/tcp/41720/p2p/12D3KooW...",
            "/ip4/172.31.255.254/tcp/41720/p2p/12D3KooW...",
            "/ip4/192.168.1.1/tcp/41720/p2p/12D3KooW...",
        ] {
            assert_eq!(
                classify_transport(raw),
                TransportKind::Unknown,
                "RFC1918 must be Unknown, not Clearnet: {raw}"
            );
        }
    }

    #[test]
    fn classify_link_local_and_metadata_endpoint_is_unknown() {
        // The cloud-metadata endpoint at 169.254.169.254 lives inside
        // the link-local range — explicitly tested because a hostile
        // SC publisher pointing here against an unsuspecting SDK
        // consumer would otherwise smuggle metadata-endpoint queries.
        assert_eq!(
            classify_transport("/ip4/169.254.169.254/tcp/80/p2p/12D3KooW..."),
            TransportKind::Unknown
        );
        assert_eq!(
            classify_transport("/ip4/169.254.0.1/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Unknown
        );
        // IPv6 link-local + ULA + multicast + unspecified.
        assert_eq!(
            classify_transport("/ip6/fe80::1/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Unknown
        );
        assert_eq!(
            classify_transport("/ip6/fc00::1/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Unknown
        );
        assert_eq!(
            classify_transport("/ip6/fd12:3456::1/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Unknown
        );
        assert_eq!(
            classify_transport("/ip6/ff02::1/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Unknown
        );
        assert_eq!(
            classify_transport("/ip6/::/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Unknown
        );
        // IPv4-mapped IPv6 must NOT smuggle a private IPv4 back in.
        assert_eq!(
            classify_transport("/ip6/::ffff:10.0.0.1/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Unknown
        );
    }

    #[test]
    fn classify_special_ip4_ranges_are_unknown() {
        // CGNAT, unspecified, broadcast, documentation, multicast.
        for raw in [
            "/ip4/100.64.0.1/tcp/41720/p2p/12D3KooW...",
            "/ip4/100.127.255.254/tcp/41720/p2p/12D3KooW...",
            "/ip4/0.0.0.0/tcp/41720/p2p/12D3KooW...",
            "/ip4/255.255.255.255/tcp/41720/p2p/12D3KooW...",
            "/ip4/192.0.2.1/tcp/41720/p2p/12D3KooW...",     // RFC5737 doc
            "/ip4/224.0.0.1/tcp/41720/p2p/12D3KooW...",     // multicast
        ] {
            assert_eq!(
                classify_transport(raw),
                TransportKind::Unknown,
                "special-range IPv4 must be Unknown: {raw}"
            );
        }
    }

    #[test]
    fn classify_routable_ipv4_is_clearnet() {
        // 203.0.113.5 lives in RFC5737 TEST-NET-3 (documentation
        // range), so it correctly classifies as Unknown — covers the
        // doc-range exclusion path. 8.8.8.8 below is the true-positive
        // boundary for routable public IPv4.
        assert_eq!(
            classify_transport("/ip4/203.0.113.5/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Unknown
        );
        // 8.8.8.8 is unambiguously public.
        assert_eq!(
            classify_transport("/ip4/8.8.8.8/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Clearnet
        );
        // Routable IPv6 (Cloudflare).
        assert_eq!(
            classify_transport("/ip6/2606:4700::1111/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Clearnet
        );
    }

    #[test]
    fn classify_garbage_is_unknown() {
        assert_eq!(classify_transport(""), TransportKind::Unknown);
        assert_eq!(classify_transport("not-a-multiaddr"), TransportKind::Unknown);
        // Future protocol with no /tcp or /quic transport.
        assert_eq!(
            classify_transport("/dns4/example.org/webrtc-direct/p2p/12D3KooW..."),
            TransportKind::Unknown
        );
        // Malformed IP literal — must NOT default to Clearnet.
        assert_eq!(
            classify_transport("/ip4/not.an.ip/tcp/41720/p2p/12D3KooW..."),
            TransportKind::Unknown
        );
    }

    #[test]
    fn transport_kind_as_str_stable() {
        // Wire string contract — clients pin these.
        assert_eq!(TransportKind::Clearnet.as_str(), "clearnet");
        assert_eq!(TransportKind::Onion.as_str(), "onion");
        assert_eq!(TransportKind::I2p.as_str(), "i2p");
        assert_eq!(TransportKind::Unknown.as_str(), "unknown");
    }

    // --- Governance decode helpers (governance-dashboard-plan.md Phase 5) ---

    #[test]
    fn bytes_be_to_decimal_zero_and_small() {
        assert_eq!(bytes_be_to_decimal_string(&[]), "0");
        assert_eq!(bytes_be_to_decimal_string(&[0x64]), "100");
        assert_eq!(bytes_be_to_decimal_string(&[0x01, 0xF4]), "500");
        assert_eq!(bytes_be_to_decimal_string(&[0xff]), "255");
    }

    #[test]
    fn bytes_be_to_decimal_round_trips_u64_values() {
        // Cross-check against Rust's own u64 formatting for a spread of
        // values, including the u64::MAX boundary.
        for v in [0u64, 1, 100, 256, 0xffff, 1_000_000, u64::MAX] {
            let bytes = v.to_be_bytes();
            let trimmed: Vec<u8> = {
                let mut i = 0;
                while i < bytes.len() - 1 && bytes[i] == 0 {
                    i += 1;
                }
                bytes[i..].to_vec()
            };
            assert_eq!(
                bytes_be_to_decimal_string(&trimmed),
                v.to_string(),
                "mismatch for {v}"
            );
        }
    }

    #[test]
    fn bytes_be_to_decimal_exceeds_u64() {
        // 2^64 = 18446744073709551616, one more than u64::MAX — exactly
        // the case a naive u64-based implementation would silently
        // truncate/corrupt. 9 bytes: 0x01 followed by 8 zero bytes.
        let bytes = {
            let mut b = vec![0x01u8];
            b.extend(std::iter::repeat(0u8).take(8));
            b
        };
        assert_eq!(
            bytes_be_to_decimal_string(&bytes),
            "18446744073709551616"
        );
    }

    #[test]
    fn decimal_to_bytes_be_zero_and_small() {
        assert_eq!(decimal_string_to_bytes_be("0").unwrap(), Vec::<u8>::new());
        assert_eq!(decimal_string_to_bytes_be("100").unwrap(), vec![0x64]);
        assert_eq!(decimal_string_to_bytes_be("500").unwrap(), vec![0x01, 0xF4]);
        assert_eq!(decimal_string_to_bytes_be("255").unwrap(), vec![0xff]);
    }

    #[test]
    fn decimal_to_bytes_be_exceeds_u64() {
        // The exact mirror of `bytes_be_to_decimal_exceeds_u64` — the
        // same value that would corrupt a naive u64-based implementation.
        let expected = {
            let mut b = vec![0x01u8];
            b.extend(std::iter::repeat(0u8).take(8));
            b
        };
        assert_eq!(
            decimal_string_to_bytes_be("18446744073709551616").unwrap(),
            expected
        );
    }

    #[test]
    fn decimal_to_bytes_be_rejects_malformed_input() {
        assert!(decimal_string_to_bytes_be("").is_err());
        assert!(decimal_string_to_bytes_be("-1").is_err());
        assert!(decimal_string_to_bytes_be("1.5").is_err());
        assert!(decimal_string_to_bytes_be("01").is_err()); // leading zero
        assert!(decimal_string_to_bytes_be("1a").is_err());
        assert!(decimal_string_to_bytes_be(" 1").is_err());
    }

    #[test]
    fn bytes_decimal_round_trip_is_lossless() {
        // Share one round-trip test across a spread of magnitudes,
        // including values requiring more than 8 bytes — proves the
        // two conversions are genuine inverses, not just independently
        // "correct-looking."
        for n in [
            "0",
            "1",
            "100",
            "255",
            "256",
            "18446744073709551615", // u64::MAX
            "18446744073709551616", // u64::MAX + 1
            "340282366920938463463374607431768211455", // u128::MAX
            "340282366920938463463374607431768211456", // u128::MAX + 1
        ] {
            let bytes = decimal_string_to_bytes_be(n).unwrap();
            assert_eq!(bytes_be_to_decimal_string(&bytes), n, "round-trip for {n}");
        }
    }

    #[test]
    fn decode_bool_bytes_wire_convention() {
        assert!(!decode_bool_bytes(&[]));
        assert!(!decode_bool_bytes(&[0x00]));
        assert!(decode_bool_bytes(&[0x01]));
    }

    #[test]
    fn proposal_summary_decodes_all_thirteen_fields() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let expected_addr = crate::crypto::pubkey_to_address(&verifying_key).unwrap();

        let items: Vec<Vec<u8>> = vec![
            vec![0x01],                          // id = 1
            verifying_key.to_bytes().to_vec(),   // proposer
            b"raise the fee".to_vec(),           // description
            b"registration_fee".to_vec(),        // param_key
            vec![0x01, 0xF4],                    // param_value = 500
            vec![0x03, 0xE8],                    // created_at = 1000
            vec![0x01, 0x51, 0x80],              // expires_at = 86400
            vec![],                              // executed = false
            vec![0x07],                          // vote_count = 7
            vec![0x02],                          // oppose_count = 2
            vec![0x0a],                          // quorum = 10
            vec![],                              // quorum_met = false
            vec![0x01],                          // supermajority_met = true
        ];
        let summary = decode_proposal_summary("listProposals", &items).unwrap();
        assert_eq!(summary.id, 1);
        assert_eq!(summary.proposer, expected_addr);
        assert_eq!(summary.description, "raise the fee");
        assert_eq!(summary.param_key, "registration_fee");
        assert_eq!(summary.param_value, "500");
        assert_eq!(summary.created_at, 1000);
        assert_eq!(summary.expires_at, 86400);
        assert!(!summary.executed);
        assert_eq!(summary.vote_count, 7);
        assert_eq!(summary.oppose_count, 2);
        assert_eq!(summary.quorum, 10);
        assert!(!summary.quorum_met);
        assert!(summary.supermajority_met);
    }

    #[test]
    fn proposal_summary_rejects_wrong_item_count() {
        assert!(decode_proposal_summary("listProposals", &[vec![0x01]]).is_err());
        assert!(decode_proposal_summary("listNodeProposals", &[]).is_err());
    }

    #[test]
    fn proposal_summary_rejects_malformed_address() {
        let mut items: Vec<Vec<u8>> = (0..13).map(|_| Vec::new()).collect();
        items[1] = vec![0u8; 31]; // wrong length, not 32
        assert!(decode_proposal_summary("listNodeProposals", &items).is_err());
    }

    #[test]
    fn proposal_tally_decodes_five_fields() {
        let items: Vec<Vec<u8>> = vec![
            vec![0x07], // vote_count = 7
            vec![0x02], // oppose_count = 2
            vec![0x0a], // quorum = 10
            vec![],     // quorum_met = false
            vec![0x01], // supermajority_met = true
        ];
        let tally = decode_proposal_tally("getNodeProposalTally", &items).unwrap();
        assert_eq!(tally.vote_count, 7);
        assert_eq!(tally.oppose_count, 2);
        assert_eq!(tally.quorum, 10);
        assert!(!tally.quorum_met);
        assert!(tally.supermajority_met);
    }

    #[test]
    fn proposal_tally_rejects_wrong_item_count() {
        assert!(decode_proposal_tally("getProposalTally", &[vec![0x01]]).is_err());
    }

    // --- End-to-end wrapper tests against a fake Klever node ---
    //
    // Per Phase 5's DoD: pure-decode unit tests above cover the shared
    // decode logic, but a copy-paste bug that sends the WRONG funcName
    // string (e.g. `get_node_proposal_count` accidentally calling
    // `get_proposal_count_generic(..., "getProposalCount")`) would
    // produce IDENTICAL decode behavior and slip past decode-only
    // tests entirely. This spins up a tiny in-process fake node
    // (mirrors `tests/ipfs_client_integration.rs`'s FakeKubo pattern)
    // that returns TRACK-DISTINGUISHABLE canned data per funcName, so
    // a wrong funcName manifests as a wrong VALUE, not just a wrong
    // route.

    use axum::{routing::post, Json, Router};
    use tokio::net::TcpListener;

    fn b64(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    async fn vm_query_handler(
        axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let func_name = body.get("funcName").and_then(|v| v.as_str()).unwrap_or("");
        let key_a = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]).verifying_key();
        let key_b = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]).verifying_key();

        let return_data: Vec<String> = match func_name {
            "listProposals" => vec![
                b64(&[0x01]),                          // id = 1
                b64(&key_a.to_bytes()),                // proposer A
                b64(b"user track"),                    // description
                b64(b"registration_fee"),               // param_key
                b64(&[0x01, 0xF4]),                    // param_value = 500
                b64(&[0x03, 0xE8]),                    // created_at
                b64(&[0x01, 0x51, 0x80]),              // expires_at
                b64(&[]),                              // executed = false
                b64(&[0x03]),                          // vote_count = 3
                b64(&[]),                              // oppose_count = 0
                b64(&[0x0a]),                           // quorum = 10
                b64(&[]),                              // quorum_met = false
                b64(&[0x01]),                          // supermajority_met = true
            ],
            "listNodeProposals" => vec![
                b64(&[0x02]),                          // id = 2 (distinct from user track)
                b64(&key_b.to_bytes()),                // proposer B (distinct)
                b64(b"node track"),                    // description (distinct)
                b64(b"node_registration_fee"),          // param_key (distinct)
                // param_value exceeds u64::MAX — proves the wrapper
                // path doesn't truncate the way a naive impl would.
                b64(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                b64(&[0x03, 0xE8]),
                b64(&[0x01, 0x51, 0x80]),
                b64(&[0x01]),                          // executed = true (distinct)
                b64(&[0x0b]),                           // vote_count = 11 (distinct)
                b64(&[0x01]),                           // oppose_count = 1 (distinct)
                b64(&[0x03]),                           // quorum = 3 (distinct)
                b64(&[0x01]),                           // quorum_met = true (distinct)
                b64(&[0x01]),                           // supermajority_met = true
            ],
            "getProposalTally" => vec![
                b64(&[0x03]), // vote_count = 3
                b64(&[]),     // oppose_count = 0
                b64(&[0x0a]), // quorum = 10
                b64(&[]),     // quorum_met = false
                b64(&[0x01]), // supermajority_met = true
            ],
            "getNodeProposalTally" => vec![
                b64(&[0x0b]), // vote_count = 11 (distinct)
                b64(&[0x01]), // oppose_count = 1 (distinct)
                b64(&[0x03]), // quorum = 3 (distinct)
                b64(&[0x01]), // quorum_met = true (distinct)
                b64(&[0x01]), // supermajority_met = true
            ],
            other => panic!("fake node received unexpected funcName: {other}"),
        };

        Json(serde_json::json!({
            "data": { "data": { "returnCode": "Ok", "returnMessage": "", "returnData": return_data } },
            "error": "",
        }))
    }

    async fn vm_hex_handler(
        axum::extract::Json(body): axum::extract::Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let func_name = body.get("funcName").and_then(|v| v.as_str()).unwrap_or("");
        let hex_data = match func_name {
            "getProposalCount" => "05",
            "getNodeProposalCount" => "07", // distinct from user track
            "getUserVote" => "01",          // VOTE_SUPPORT
            "getNodeVote" => "02",          // VOTE_OPPOSE (distinct)
            other => panic!("fake node received unexpected funcName: {other}"),
        };
        Json(serde_json::json!({
            "data": { "data": hex_data },
            "error": "",
        }))
    }

    async fn spawn_fake_klever_node() -> String {
        let app: Router = Router::new()
            .route("/vm/query", post(vm_query_handler))
            .route("/vm/hex", post(vm_hex_handler));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn governance_wrappers_send_correct_func_names_and_decode_correctly() {
        let node_url = spawn_fake_klever_node().await;
        let http = reqwest::Client::new();
        let contract = "klv1qqqqqqqqqqqqqpgq0000000000000000000000000000000000000000";

        // Counts — distinct values per track prove funcName routing.
        assert_eq!(
            get_proposal_count(&http, &node_url, contract).await.unwrap(),
            5
        );
        assert_eq!(
            get_node_proposal_count(&http, &node_url, contract)
                .await
                .unwrap(),
            7
        );

        // Vote status — distinct values per track.
        let owner = crate::crypto::pubkey_to_address(
            &ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]).verifying_key(),
        )
        .unwrap();
        assert_eq!(
            get_user_vote(&http, &node_url, contract, 1, &owner)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            get_node_vote(&http, &node_url, contract, 1, &owner)
                .await
                .unwrap(),
            2
        );

        // Tallies — distinct values per track.
        let user_tally = get_proposal_tally(&http, &node_url, contract, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user_tally.vote_count, 3);
        assert_eq!(user_tally.quorum, 10);
        let node_tally = get_node_proposal_tally(&http, &node_url, contract, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(node_tally.vote_count, 11);
        assert_eq!(node_tally.quorum, 3);

        // Lists — distinct rows per track, including the >u64::MAX
        // param_value on the node-track row round-tripping correctly
        // through the real HTTP + decode path (not just the isolated
        // decode-function unit test above).
        let user_rows = list_proposals(&http, &node_url, contract, 0, 20)
            .await
            .unwrap();
        assert_eq!(user_rows.len(), 1);
        assert_eq!(user_rows[0].id, 1);
        assert_eq!(user_rows[0].description, "user track");
        assert_eq!(user_rows[0].param_value, "500");
        assert!(!user_rows[0].executed);

        let node_rows = list_node_proposals(&http, &node_url, contract, 0, 20)
            .await
            .unwrap();
        assert_eq!(node_rows.len(), 1);
        assert_eq!(node_rows[0].id, 2);
        assert_eq!(node_rows[0].description, "node track");
        assert_eq!(node_rows[0].param_value, "18446744073709551616");
        assert!(node_rows[0].executed);
        assert_ne!(node_rows[0].proposer, user_rows[0].proposer);
    }

    /// Live-network check against the REAL testnet contract (SC 0.8.0,
    /// upgraded 2026-08-25, governance-dashboard-plan.md Phase 4) — not
    /// run by default (`cargo test`), only via `cargo test -- --ignored`,
    /// since it needs network access and depends on live chain state.
    /// No `#[ignore]`-gated test convention existed elsewhere in this
    /// codebase before this one; added because it closes the loop
    /// between Phase 4's manual `curl`-based verification and this
    /// phase's actual Rust client code — proving the real `reqwest`
    /// HTTP path decodes the real Klever RPC response shape correctly,
    /// not just the fake server above. Kept (not deleted after one run)
    /// as regression coverage for future SC upgrades.
    #[tokio::test]
    #[ignore]
    async fn governance_views_work_against_live_testnet() {
        let http = reqwest::Client::new();
        let node_url = "https://node.testnet.klever.org";
        let contract = "klv1qqqqqqqqqqqqqpgq0ja2j7xwz843ryfsk9vlz6xzsaak590h6pgq7nwr02";

        // As of the Phase 4 upgrade, no proposals exist on either track
        // yet — this proves the "empty" paths work against a real node,
        // matching the Phase 4 curl-based verification.
        assert_eq!(
            get_proposal_count(&http, node_url, contract).await.unwrap(),
            0
        );
        assert_eq!(
            get_node_proposal_count(&http, node_url, contract)
                .await
                .unwrap(),
            0
        );
        assert!(list_proposals(&http, node_url, contract, 0, 20)
            .await
            .unwrap()
            .is_empty());
        assert!(list_node_proposals(&http, node_url, contract, 0, 20)
            .await
            .unwrap()
            .is_empty());
        // A nonexistent proposal ID must decode as "not found", not error.
        assert!(get_proposal_tally(&http, node_url, contract, 1)
            .await
            .unwrap()
            .is_none());
        assert!(get_node_proposal_tally(&http, node_url, contract, 1)
            .await
            .unwrap()
            .is_none());
        // The testnet SC owner has never voted on anything.
        let owner = "klv1heatuswg9u9u356snvj20fn9jvcgva8fea5v54uhqadchhaz6pgq26t8jh";
        assert_eq!(
            get_user_vote(&http, node_url, contract, 1, owner)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            get_node_vote(&http, node_url, contract, 1, owner)
                .await
                .unwrap(),
            0
        );
    }
}
