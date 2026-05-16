//! Klever anchor verification for snapshot bootstrap (spec 11-snapshot-sync.md §5a.5 Phase 3).
//!
//! The snapshot client trusts a peer's manifest only up to the highest
//! anchor whose `state_root` matches what's actually on the Klever chain.
//! Originally wrapped `getStateRoot(block_height)`; as of l2-node 0.44.0
//! (spec 12 §5.2 LN2.7) the underlying SC call is `getCanonicalAnchor`
//! — the quorum-confirmed root for v0.3+ heights. Pre-v0.3 heights
//! become invisible to bootstrap verification, which is intentional:
//! all live nodes are post-v0.3 by the time this release deploys.
//!
//! Compared to the chain scanner's batch event scanning, this is a
//! point query: one HTTP roundtrip per anchor. With ~24 anchors/day at
//! the default anchoring interval, verifying a years-old snapshot is
//! at most a few tens of requests — small even on a rate-limited
//! Klever API.

use anyhow::Result;

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

/// Query the canonical (quorum-confirmed) state root for a height.
///
/// **As of l2-node 0.44.0** this delegates to
/// [`crate::chain::sc_views::get_canonical_anchor`], which calls the SC's
/// `getCanonicalAnchor(block_height)` view. The function name is retained
/// for caller stability — most call sites read this as "query Klever for
/// what root it has at this height", which is exactly what's still happening,
/// just against the hybrid-aware view instead of the legacy `getStateRoot`
/// shim (spec 12 §5.2 LN2.7).
///
/// Returns:
/// - `Ok(Some(state_root_hex))` when the SC has a canonical (quorum-
///   confirmed) anchor at this height. For heights in hybrid-escalated
///   mode, the SC returns the escalated_canonical OR the deterministic
///   §2.9 tiebreak winner (read-only — no on-chain write triggered by
///   this view call).
/// - `Ok(None)` when the SC has no canonical anchor at this height —
///   either because quorum hasn't been reached, OR (as of 0.44.0) the
///   height pre-dates the SC v0.3.0 upgrade. Snapshot bootstrap treats
///   both cases the same: walk DOWN looking for the next valid anchor.
/// - `Err(...)` on transport/decoding errors.
pub async fn query_klever_state_root_at(
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
    block_height: u64,
) -> Result<Option<String>> {
    crate::chain::sc_views::get_canonical_anchor(
        http,
        klever_node_url,
        contract_address,
        block_height,
    )
    .await
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

    // Note: the `u64_minimal_hex_matches_anchoring_path` test moved to
    // chain::sc_views::tests as of l2-node 0.44.0, when anchor_verify
    // stopped owning its own encoding helper and delegated to
    // sc_views::get_canonical_anchor instead. See spec 12 §5.2 LN2.7.

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
