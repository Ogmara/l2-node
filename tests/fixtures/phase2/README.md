# Phase-2 golden vectors (`vectors.json`)

Cross-implementation fixtures for the private-channel "verify before cover"
work (l2-node 0.142.0, sdk-js `verifyPrivateMemberProof`). The SDK's verifier
must reproduce every byte (claim strings, signatures) and every verdict here.

## How they are generated

`vectors.json` is written by the l2-node unit test
`api::phase2_fixtures::golden_vectors` (`src/api/phase2_fixtures.rs`):

```sh
# regenerate (review the diff before committing)
OGMARA_REGEN_PHASE2_FIXTURES=1 cargo test golden_vectors
# verify the committed file is current (fails on any drift, and fails if the
# file is missing — it is never silently recreated)
cargo test golden_vectors
```

* All keys come from fixed seeds (`keys.*.seed_hex`, Ed25519 secret-key
  bytes), all timestamps from `base_timestamp_ms`, and Ed25519 is
  deterministic — so the file is byte-stable across runs and machines.
* Envelopes are MessagePack (`rmp_serde::to_vec_named`, map form) and are
  given as standard base64 with padding, exactly as `POST
  /api/v1/channels/{id}/member-proofs` serves them.
* Every case's `expected` verdict is ASSERTED against the node's own join
  gate (`verify_embedded_envelope` + `verify_private_join`, sync semantics:
  a moderator demotion kills a grant only when `grant.ts < rm.ts <=
  invite.ts`) on a fresh router after replaying the case's
  `setup_envelopes`; `node_reason` is the node's rejection message. A
  vector can therefore not disagree with the node.

## Contents

* `claims.wallet_direct` — pchansync claim, wallet-signed:
  `ogmara-private-channel-sync-auth:{network}:{nodeId}:{wallet}:{ts}`.
* `claims.device_signed` — pchansync claim signed by the delegated device:
  `ogmara-private-channel-sync-device-auth:{network}:{nodeId}:{wallet}:{device_pubkey_hex}:{ts}`,
  plus the wallet's delegation signature over
  `ogmara-device-claim:{network}:{device_pubkey_hex}:{wallet}:{ts}`.
  Signatures are Klever-message signatures (`\x17Klever Signed Message:\n`
  + length + message → Keccak-256 → Ed25519).
* `enc_binding` — a `DeviceEncBinding` wallet signature over
  `ogmara-enc-bind:{network}:{enc_pub}:{device_id}:{wallet}:{ts}` as served by
  `GET /api/v1/users/{address}/enc-keys` (`"bound": true`).
* `cases[]` — one member-proof bundle per verifier case, using the same
  field names as `POST /api/v1/channels/{id}/member-proofs` (format
  `ogmara-phase2-golden-vectors/2`): `channel_create`, `join`, `removals`,
  `moderator_grants` / `moderator_removals` (maps keyed by moderator
  address), `device_claims` (map keyed by device address; each object has
  `delegations[]` with wallet AND device signatures and `revocations[]`
  raw DeviceRevocation envelopes — apply the time window: a delegation
  covers an envelope at `t` iff `delegation.ts <= t` and no revocation `R`
  has `delegation.ts <= R.ts <= t`), `activation_ms` (the legacy-activation
  constant the verifier must apply for that case), `expected` (`valid` /
  `invalid`). Cases: valid creator invite, moderator invite with grant,
  moderator invite with the grant served separately (fallback), grant
  signed by a non-creator, wrong target, wrong channel, expired, invite
  dated > join + 5 min, kick cutoff (creator kick and moderator kick with
  the remover's grant), kicked then re-invited (valid), grant killed by
  RemoveModerator, device-signed join (valid), forged device claim, join by
  a device revoked AFTER it signed (valid) and BEFORE it signed (invalid),
  Klever-wrapped invite signature (valid), tampered msg_id, wrong network,
  nested Join in the invite slot, oversized invite, legacy join before /
  after activation.
