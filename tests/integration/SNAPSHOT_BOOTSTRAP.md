# Manual Integration Test — Phase 2 Snapshot Bootstrap

> Spec: `docs/specs/11-snapshot-sync.md`
> Code: `src/network/snapshot_client.rs`
> Released in: **v0.35.0** (experimental, opt-in)

Automated 3-node libp2p integration tests are deferred to a future
release. Until they land, validate Phase 2 against a real network with
this procedure. **All steps assume testnet** — never run an experimental
bootstrap against mainnet until Phase 3 ships.

## What we're proving

1. A fresh L2 node with `bootstrap_enabled = true` can fetch a snapshot
   from already-running peers and skip block-by-block Klever scanning.
2. The applied state matches the source nodes (USERS, CHANNELS,
   CHANNEL_MEMBERS, DELEGATIONS, STATE_ANCHORS, ANCHOR_BY_NODE).
3. The rollback checkpoint is created BEFORE the apply and is restorable
   if the apply is interrupted.
4. The chain scanner resumes correctly from the new `chain_cursor`.

## Prerequisites

- At least **3 nodes** running v0.34.0+ on testnet with
  `snapshot.serve_enabled = true`, all anchored, all with the same
  snapshot root.
- A fresh **fourth node** with an empty `data_dir` (or rename the
  existing `db/` aside).
- All four nodes share `bootstrap_nodes`, `network_id`, and
  `klever.contract_address`.

## Procedure

### 1. Verify the existing three nodes are serving snapshots

On each running node:

```bash
curl -s http://localhost:41721/admin/snapshot/status | jq .
```

Each must return `"available": true` and the same `snapshot_root` value.
If the roots differ, wait for the next rebuild cycle
(`serve_rebuild_interval_secs`, default 3600s) and re-check.

### 2. Configure the fresh node

In the new node's `ogmara.toml`:

```toml
[snapshot]
serve_enabled = true
bootstrap_enabled = true
experimental_skip_anchor_verify = true   # required in Phase 2
bootstrap_only_if_fresh = true
allow_apply_over_existing = false
quorum_sample_size = 5
quorum_min_peers = 3                     # must match number of available peers
parallel_fetches = 3
chunk_retries = 5
discovery_timeout_secs = 60              # bump from default 30 for first run
```

### 3. Start the fresh node and watch the logs

```bash
RUST_LOG=info,ogmara_node::network::snapshot_client=debug \
  ./ogmara-node run --config ogmara.toml 2>&1 | tee bootstrap.log
```

Expected log sequence:

```
INFO Phase 2 snapshot bootstrap starting (experimental)
INFO Probing peers for snapshot availability   candidates=3
INFO Snapshot quorum reached                   block_height=<H> agreeing_peers=3
INFO Manifest fetched and validated            cfs=6
INFO All chunks fetched and verified           chunks=<N>
INFO Applying snapshot to local storage
INFO Rollback checkpoint created               rollback_dir=...
INFO Snapshot apply complete                   applied_at=<H>
INFO Snapshot bootstrap succeeded
```

### 4. Verify post-apply state

```bash
# Check the chain cursor was set:
curl -s http://localhost:41721/api/v1/health | jq '.chain_cursor'
# Should match the cutoff_height from the log (usually == snapshot block_height
# until Phase 3 anchor verification refines it).

# Check user/channel counts vs. one of the source nodes:
diff <(curl -s http://localhost:41721/api/v1/users/search?q=k -o /dev/stdout | jq -S .) \
     <(curl -s http://<source_node>:41721/api/v1/users/search?q=k -o /dev/stdout | jq -S .)
```

Both nodes should agree on the user list.

### 5. Verify the rollback dir is present

```bash
ls -la data/snapshot_rollback_*/
```

A directory should exist with RocksDB SST files (hard-linked from the
pre-apply state). After the chain scanner has caught up past the
cutoff height + a buffer of blocks, this directory becomes safe to
delete. **Phase 2 does not yet garbage-collect it automatically** —
operators can delete it manually once they've confirmed the apply.

### 6. Verify chain scanner resumes correctly

Watch the log for the scanner picking up where the snapshot left off:

```
INFO chain::scanner Chain scanner initialized   last_block=<cutoff_height>
INFO chain::scanner Processing block range      start=<cutoff_height+1> ...
```

The scanner should NOT re-scan blocks below `cutoff_height`.

## Failure / rollback scenarios

### A. Force a quorum failure

Stop one of the three source nodes so only two remain. Restart the fresh
node. Expect:

```
WARN Snapshot bootstrap aborting: not enough peers within discovery timeout
WARN Snapshot bootstrap skipped — falling back to chain scan
```

The node then proceeds to scan Klever block-by-block as before.

### B. Force an apply crash

After step 3 begins ("Applying snapshot to local storage"), kill the
process with `kill -9` before "Snapshot apply complete" appears. Restart
the node. The `SNAPSHOT_APPLIED_AT_HEIGHT` sentinel will be absent but
the `snapshot_rollback_*` directory will exist.

> **Phase 2 limitation:** automatic rollback-on-restart is **not yet
> implemented**. After a crashed apply, manually restore by stopping
> the node, replacing `data/db/` with the contents of
> `data/snapshot_rollback_<ts>/`, and starting again. Phase 3 will wire
> automatic restoration.

### C. Hash-tampered chunk

This is hard to force without a malicious peer. The unit test
`storage::snapshot::tests::decode_chunk_rejects_tampered_payload` covers
the code path. If a peer ever does serve a bad chunk, expect:

```
WARN Snapshot outbound request failed
WARN Snapshot bootstrap failed — falling back to chain scan
```

## What to capture if anything goes wrong

1. The full log (`bootstrap.log`).
2. `curl http://localhost:41721/admin/snapshot/status | jq .` from the
   target AND each source node.
3. `ls -la data/snapshot_rollback_*/` from the target.
4. Output of `ls -la data/db/` (rocks DB size).
5. The four nodes' `ogmara.toml` config files (redact secrets).

## Future automation

Phase 3 (v0.36) ships with proper integration tests in `tests/`. The
plan is a `tokio::test` that spawns 3 in-process libp2p nodes, exchanges
identifies, builds a snapshot on the first, kills the second, and
asserts the bootstrap path applies correctly. That harness will
supersede this document.
