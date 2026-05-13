//! Klever anchor verification for snapshot bootstrap (spec 11-snapshot-sync.md §5a.5 Phase 3).
//!
//! The snapshot client trusts a peer's manifest only up to the highest
//! anchor whose `state_root` matches what's actually on the Klever chain.
//! This module wraps the Ogmara KApp's `getStateRoot(block_height)` view
//! function (spec 02-onchain.md:745) so the bootstrap orchestrator can
//! check anchors top-down and find the cutoff.
//!
//! Compared to the chain scanner's batch event scanning, this is a
//! point query: one HTTP roundtrip per anchor. With ~24 anchors/day at
//! the default anchoring interval, verifying a years-old snapshot is
//! at most a few tens of requests — small even on a rate-limited
//! Klever API.

use anyhow::{Context, Result};

/// Minimal big-endian even-length hex encoding of a u64 (Klever VM convention).
///
/// `0` → `"00"`, `1` → `"01"`, `256` → `"0100"`, `0xFF` → `"ff"`. The SC
/// decodes each arg as raw big-endian bytes; using minimal form matches
/// what the anchoring TX builder emits (`chain::anchoring::encode_u64_hex`)
/// so both paths produce identical wire arguments.
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

/// Result of one anchor's verification round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorVerifyOutcome {
    /// On-chain state_root matches the snapshot's claim — the anchor is good.
    Match,
    /// The anchor exists on-chain but state_root differs.
    /// **Poisoned snapshot** — the peer cannot have constructed this anchor honestly.
    Mismatch {
        on_chain: String,
        in_snapshot: String,
    },
    /// The smart contract doesn't have an anchor at this height
    /// (`require!` failure on the view function: "Anchor not found").
    NotAnchored,
    /// Klever RPC was unreachable. Treated as soft-fail by the
    /// orchestrator — caller decides whether to retry or accept the
    /// already-verified cutoff.
    RpcError(String),
}

/// Query the Ogmara KApp's `getStateRoot(block_height)` view function.
///
/// Returns:
/// - `Ok(Some(state_root_hex))` when the SC has an anchor at this height.
///   The hex string is the same 64-character form stored in
///   `StateAnchorRecord.state_root`.
/// - `Ok(None)` when the SC reports no anchor at this height
///   (`require!` failure on `state_root(block_height).is_empty()`).
/// - `Err(...)` on transport/decoding errors.
///
/// **Note on encoding:** Klever VM args are hex-encoded bytes. A u64
/// passes as the 8-byte big-endian representation (16 chars). The full
/// 8-byte form is always even-length and unambiguous; minimal-encoding
/// is unnecessary here. See feedback memory "Klever SC Call Data
/// Encoding Patterns" for the broader rules.
pub async fn query_klever_state_root_at(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    block_height: u64,
) -> Result<Option<String>> {
    let url = format!("{}/vm/hex", klever_node_url.trim_end_matches('/'));
    // Klever VM args are minimal big-endian even-length hex bytes (matches
    // the `encode_u64_hex` helper used by the anchoring TX path). Sending
    // the full 8-byte form would also decode, but minimal-BE is the
    // canonical form the SC sees on-chain, so we match it exactly.
    let height_hex = encode_u64_minimal_hex(block_height);

    let body = serde_json::json!({
        "scAddress": contract_address,
        "funcName": "getStateRoot",
        "args": [height_hex],
    });

    // Client-level timeout is already 15s (set by the caller's
    // reqwest::Client::builder()), no per-request override needed.
    let resp: serde_json::Value = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("POST /vm/hex for getStateRoot")?
        .json()
        .await
        .context("decoding /vm/hex response")?;

    // Klever returns errors via top-level "error" or "code" != "successful".
    // `require!` failures appear with a non-empty "error" string and
    // an empty "data" payload. We treat "Anchor not found" as a normal
    // "not present" answer, not a transport error.
    if let Some(err) = resp.get("error").and_then(|v| v.as_str()) {
        if !err.is_empty() {
            if err.contains("Anchor not found") || err.contains("not found") {
                return Ok(None);
            }
            anyhow::bail!("getStateRoot returned error: {}", err);
        }
    }

    let hex_data = resp
        .pointer("/data/data")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if hex_data.is_empty() {
        // No data and no error = no anchor at this height.
        return Ok(None);
    }

    // The SC stores `state_root: ManagedBuffer` whose `.len() == 64`,
    // meaning the SC stores the ASCII-encoded hex string (not raw 32
    // bytes). The VM /hex endpoint returns those ASCII bytes as hex,
    // so two hex-encodings deep: hex::decode → ASCII bytes →
    // String::from_utf8 → the 64-char hex string we'll compare.
    let ascii_bytes =
        hex::decode(hex_data).context("hex-decoding /vm/hex data payload")?;
    let state_root = String::from_utf8(ascii_bytes)
        .context("getStateRoot payload is not valid UTF-8")?;
    if state_root.len() != 64 {
        anyhow::bail!(
            "getStateRoot returned unexpected length: got {}, expected 64",
            state_root.len()
        );
    }
    Ok(Some(state_root))
}

/// Compare a snapshot's anchor against on-chain truth.
///
/// Returns one of:
/// - `Match` — accept this anchor as a valid cutoff candidate.
/// - `Mismatch` — caller should abort bootstrap (snapshot is poisoned).
/// - `NotAnchored` — caller continues searching downwards.
/// - `RpcError` — caller decides per its retry budget.
pub async fn verify_anchor(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    block_height: u64,
    expected_state_root: &str,
) -> AnchorVerifyOutcome {
    match query_klever_state_root_at(http, klever_node_url, contract_address, block_height).await {
        Ok(Some(on_chain)) => {
            if on_chain.eq_ignore_ascii_case(expected_state_root) {
                AnchorVerifyOutcome::Match
            } else {
                AnchorVerifyOutcome::Mismatch {
                    on_chain,
                    in_snapshot: expected_state_root.to_string(),
                }
            }
        }
        Ok(None) => AnchorVerifyOutcome::NotAnchored,
        Err(e) => AnchorVerifyOutcome::RpcError(format!("{:#}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_minimal_hex_matches_anchoring_path() {
        // Same expectations as `chain::anchoring::encode_u64_hex` tests —
        // the two helpers MUST produce identical output so the receive path
        // verifies against the same byte representation the producer
        // emitted when anchoring on-chain.
        assert_eq!(encode_u64_minimal_hex(0), "00");
        assert_eq!(encode_u64_minimal_hex(1), "01");
        assert_eq!(encode_u64_minimal_hex(100), "64");
        assert_eq!(encode_u64_minimal_hex(256), "0100");
        assert_eq!(encode_u64_minimal_hex(0xFF), "ff");
        assert_eq!(encode_u64_minimal_hex(0xABCD), "abcd");
        // u64::MAX is 16 hex chars (always even length).
        assert_eq!(encode_u64_minimal_hex(u64::MAX), "ffffffffffffffff");
    }

    #[test]
    fn outcomes_compare_correctly() {
        let m = AnchorVerifyOutcome::Match;
        let na = AnchorVerifyOutcome::NotAnchored;
        assert_ne!(m, na);
        let mm1 = AnchorVerifyOutcome::Mismatch {
            on_chain: "aa".into(),
            in_snapshot: "bb".into(),
        };
        let mm2 = AnchorVerifyOutcome::Mismatch {
            on_chain: "aa".into(),
            in_snapshot: "bb".into(),
        };
        assert_eq!(mm1, mm2);
    }
}
