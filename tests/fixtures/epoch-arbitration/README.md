# Key-epoch arbitration golden vectors (`vectors.json`)

Cross-implementation fixtures for node-side key-epoch arbitration
(l2-node 0.143.0, protocol §8.1 / §8.1.2, sdk-js `channelKeyCommit.ts` /
`buildChannelEpochKeyEnvelope`).

## How they are generated

`vectors.json` is written by the l2-node unit test
`api::epoch_arbitration_tests::epoch_arbitration_golden_vectors`
(`src/api/epoch_arbitration_tests.rs`):

```sh
# regenerate (review the diff before committing)
OGMARA_REGEN_EPOCH_FIXTURES=1 cargo test epoch_arbitration_golden_vectors
# verify the committed file is current (fails on drift or if missing)
cargo test epoch_arbitration_golden_vectors
```

All keys come from fixed seeds (`signer_seed_hex` = Ed25519 secret-key
bytes), all timestamps are fixed, and Ed25519 is deterministic, so the file
is byte-stable. Every envelope's `expected` outcome is ASSERTED against the
node's own router (submitted through the LIVE pipeline at a fixed node
clock of `timestamp + 1000` ms, on a fresh database holding the `channel` in
the file), so a vector cannot disagree with the node. (Since 0.143.0's
round-2 fixes, sync/backfill ingestion only accepts wraps of an ALREADY
recorded winner — `400 key_sync_not_winner` otherwise — so the vectors can
no longer be replayed through the sync path.)

## Contents

* `commitment.kat[]` — known-answer tests for
  `key_commitment = keccak256("ogmara-chankey-commit-v1" || key_scope[32] ||
  epoch_be8 || key_ts_be8 || channel_key[32])`, with every input, the full
  preimage and the result. `key_scope = keccak256("ogmara-channel-scope-v1"
  || channel_id_be8)`. `key_ts` is bound into the hash (audit B2, replacing
  the earlier draft without it): a candidate key is the PAIR
  `(key_ts, key_commitment)`, and a commitment cannot be re-ranked by
  editing `key_ts` alone.
  Pinned in `key_commitment_kat` and cross-checked against an independent
  Keccak-256 (`@noble/hashes` `keccak_256`):
  * scope(2^32+1) = `7085627c…c952`, epoch 7, key_ts 1790000000000, key
    `00..1f` → `8016166a572c3b83cf9547a51877d8f7bd66ee26ac19d2ca74c74fe55268a5d4`
  * scope 32×`00`, epoch 1, key_ts 1, key 32×`00` →
    `bcd39e590bd58ecaf69b25e13032a70829f47e98c1f33d20d976dd2ed9208d32`
  sdk-js `channelKeyCommit.test.ts` and spec 01 §8.1 must carry these
  values (the earlier `15a7b3db…` / `c674de17…` vectors are obsolete).
* `rank` — the arbitration rule and its constants (`finality_ms` 120000,
  `key_ts_max_age_ms` 900000: an envelope with `timestamp - key_ts` above it
  is refused with `key_ts_stale` unless its pair is the current winner).
* `envelopes[]` — signed `ChannelKeyEnvelope` (0x61) vectors:
  * `winner_epoch2` — a valid commitment-bearing envelope → accepted,
    `key_status: "stored"`.
  * `rival_epoch2_worse_rank` — a different key for the same epoch with a
    later `key_ts` → `KeyConflict`; `expected.http_409` is the exact 409
    JSON body `POST /api/v1/messages` returns for it.
  * `commitment_less_new_epoch` — no `key_commitment`/`key_ts` at a fresh
    epoch → `400 {"error":"key_commitment_required"}` (STRICT policy).

  For each: `payload_fields` (decoded), `payload_msgpack_hex` (the payload
  bytes exactly as sdk-js `buildChannelKeyEnvelope` emits them —
  `@msgpack/msgpack` map in insertion order `key_scope, scope_kind, epoch,
  target, device_id, peer (nil), channel_id, eph_pub, nonce, wrapped,
  key_commitment, key_ts`; byte arrays as `bin`, integers as the smallest
  `uint`, `key_ts` never a float), `msg_id_hex`, `signature_hex` and
  `envelope_msgpack_hex` (the full envelope, Rust map encoding).

  `msg_id` and the signature cover only the payload bytes, the author key,
  the timestamp and the network — a JS client must reproduce
  `payload_msgpack_hex` byte for byte; the outer envelope encoding may
  differ (the node accepts any equivalent msgpack form).
