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
}
