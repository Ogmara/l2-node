# Changelog

All notable changes to the Ogmara L2 node will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.40.0] - 2026-05-15

### Added
- **Media handler tunables are now config-driven.** Three new fields
  in `IpfsConfig`, with defaults matching the v0.39 hardcoded values:
  - `media_cache_total_mb` (default 256) — total LRU weight
  - `media_cache_item_mb` (default 16) — per-item cache cap
  - `media_handler_permits` (default 32) — concurrent handlers
  Operators can now tune these in `ogmara.toml` without a recompile;
  existing TOMLs continue to work unchanged (all fields are
  `#[serde(default)]`). Resource-constrained nodes can lower the
  values; high-throughput nodes can raise them.
- **`If-Range` support** (RFC 7233 §3.2). Clients resuming a partial
  download can send `Range: bytes=N-` plus `If-Range: "<etag>"`; if
  the ETag still matches the current resource, we return 206
  Partial Content. If it doesn't, we ignore the Range and return the
  full body so the client can rebuild from scratch. For
  content-addressed CIDs the ETag is the CID itself, so a match is
  guaranteed for the same content — this is mostly defensive
  correctness against future ETag schemes.
- **`src/lib.rs` library target** alongside the existing binary.
  Re-exports `config` and `ipfs` modules so integration tests in
  `tests/` can construct `IpfsClient` against a fake-Kubo server.
  The binary's module tree is unchanged; this is additive.
- **Integration test suite against a fake Kubo**
  (`tests/ipfs_client_integration.rs`). Spawns an in-process axum
  server mimicking Kubo's `/api/v0/cat` and `/api/v0/files/stat`
  endpoints, then exercises `IpfsClient` end-to-end through
  `reqwest`. 8 scenarios cover: full GET, ranged GET, truncated
  range responses, `Size` field reading, `offline=true` flag flow,
  and the two flavors of "not local" Kubo signalling (500 status
  AND `200 + {"Error": ...}`).

### Fixed (audit-driven hardening)
- **`exists_local` now defends against future Kubo behavior changes.**
  The pre-0.40 implementation trusted the HTTP status alone: 2xx
  meant "local exists". Kubo has historically also signalled
  "not local" with `200 OK + {"Error": ...}` in the response body,
  and could plausibly flip back to that convention in a future
  build. The new code reads the body (bounded to 8 KiB) and treats
  any `Error` key as "not local", regardless of HTTP status —
  closing a small confirmation-oracle window in the
  `If-None-Match` 304 short-circuit.
- **`exists_local` response also bounded at 8 KiB.** Same
  defense-in-depth as `get_size`: a hostile/corrupted Kubo could
  otherwise stream gigabytes of JSON into the lightweight probe.

### Tests
- **45 unit tests in `media_tests`** (was 41 in v0.39) — added 4
  HEAD tuple-form regression tests locking the
  no-double-Content-Length guarantee for both 200 and 206
  responses. A future contributor re-adding a body to the HEAD
  branch trips these immediately.
- **8 integration tests in `ipfs_client_integration`** as above.

### Migration notes
- **Existing `ogmara.toml` files continue to work** — the new fields
  default to the v0.39 hardcoded values. Operators wanting to tune
  media handler resources can add an `[ipfs]` section with any of
  the new fields, or leave the defaults.
- **`AppState::with_broadcast` gained a `MediaTuning` parameter.**
  Only `node.rs` calls this in production; `AppState::new()` passes
  `MediaTuning::default()` for tests. Internal API change only —
  no impact on external callers.

### Security hardening (audit-driven)
- **`Config::validate` now rejects degenerate / abusive media
  tunables at startup.** A misconfigured `media_handler_permits = 0`
  would have made every `/api/v1/media/:cid` request block forever
  (the semaphore yields no permits); huge values like
  `usize::MAX` would have reverted the v0.39 memory-amplification
  mitigation. The new checks reject zero, oversized values
  (`permits > 4096`, `cache_total > 64 GiB`), inconsistent
  combinations (`item_mb > total_mb`, `item_mb > max_upload_mb`).
  Audit critical fix.
- **Streaming size cap on `get_size` + `exists_local` bodies.**
  v0.39's post-buffer length check would still let a chunked-
  transfer Kubo stream gigabytes before the 8 KiB cap fired (the
  cheap Content-Length pre-check is skipped when no header is
  declared). The new `read_body_capped` helper enforces the cap
  INCREMENTALLY as bytes arrive, aborting the read at the boundary.
  Audit warning W-2 (security) fix.
- **`usize::try_from` for `media_cache_item_mb` → bytes
  conversion** (node.rs). v0.39's `as usize` cast would have
  silently truncated values larger than `u32::MAX` on 32-bit
  targets (armv7, i686). Saturating-conversion via `try_from` is
  a no-op on 64-bit and correct on 32-bit. Audit warning W-3
  (security) fix.

### Test cleanup
- **Removed unnecessary startup sleep** in the fake-Kubo
  integration test. `TcpListener::bind` is awaited before the
  axum `serve` spawn, so the OS already has the socket listening
  before any connection attempt — the sleep was cargo-cult and
  slowed every test invocation. Audit warning W-3 (code) fix.
- **Removed dead `fail_sniff_prefix` field** from the test
  harness — referenced by `cat_handler` but never set by any
  committed test. Sniff-failure handling is well-covered in the
  unit test layer.

### Deferred to v0.41 (or later)
- Promote per-IP semaphore sub-cap to prevent single-IP
  saturation of the configured permits. Apache rate-limit in
  front (documented since v0.38) covers this in production.
- Optional `Last-Modified` header — CIDs don't have a natural
  modification time, so this would need to come from the upload
  timestamp tracked elsewhere; not yet worth the wiring cost.
- `If-Range` HTTP-date support — RFC 7233 §3.2 allows
  `HTTP-date` as well as `entity-tag` in `If-Range`. The current
  impl drops Range silently for date-form (safe fallback, full
  body). Future enhancement, not a regression.

## [0.39.0] - 2026-05-15

### Fixed
- **Memory-amplification DoS vector on `/api/v1/media/:cid` closed.**
  v0.38 added Range support but still buffered the full IPFS blob on
  every request and had no concurrency cap. A botnet issuing rolling
  Range requests against a 50 MB asset could trivially push the node
  past memory exhaustion (200 clients × 50 MB ≈ 10 GB transient RSS).
  v0.39 lands the three-part fix the v0.38 CHANGELOG tracked:
  - **Streaming IPFS reads** via the new `IpfsClient::get_range(cid,
    offset, length)` method (Kubo `cat?offset=&length=`). Range
    requests against files larger than `MEDIA_CACHE_ITEM_BYTES` (16 MB)
    fetch ONLY the requested bytes — no full-blob buffering ever.
  - **Bounded LRU cache for hot media** (`moka::future::Cache`).
    Capped at `MEDIA_CACHE_TOTAL_BYTES` (256 MB total, weighted by
    item size) and per-item at `MEDIA_CACHE_ITEM_BYTES` (16 MB).
    Hot small items (thumbnails, frequently-viewed images) serve
    from memory; large items always stream from IPFS.
  - **Semaphore on concurrent media handlers**
    (`MEDIA_HANDLER_PERMITS` = 32). Further requests queue rather
    than spawning unbounded fetch + slice tasks. Combined with the
    per-fetch `max_upload_bytes`, peak transient RSS is now bounded
    at roughly `permits × max_upload`.

### Added
- **`HEAD /api/v1/media/:cid` handler** (RFC 9110 §9.3.2). Same
  headers as GET, empty body. Players probing for `Accept-Ranges`
  no longer need to issue a full GET; cache-fresh clients can
  re-validate with `If-None-Match` against the ETag in a single
  HEAD round-trip. Mitigates the memory amplification further by
  not requiring any IPFS body fetch for probe-only traffic.
- **`Content-Disposition` header on every media response.**
  - `inline; filename="<cid>"` for known media types — browser
    renders inline in `<img>`, `<video>`, `<audio>`.
  - `attachment; filename="<cid>"` for `application/octet-stream`
    fallback — opaque blobs download rather than render. Hardens
    against any future MIME-sniffing regression even though
    `X-Content-Type-Options: nosniff` is already set.
- **`IpfsClient::get_size(cid)`** — offline-only stat call
  (`files/stat?offline=true`) returning the actual `Size` field.
  Used by the media handler for both Range bounds validation and
  cache-eligibility decisions before any bytes leave the IPFS node.
- **`IpfsClient::exists_local(cid)`** — companion offline-only
  existence probe used by the `If-None-Match` 304 short-circuit.
  No DHT walks — an attacker probing fabricated CIDs can no longer
  pin Kubo into network resolution.

### Changed
- **`IpfsClient::get()` now returns `bytes::Bytes` instead of
  `Vec<u8>`.** Reference-counted, zero-copy share. Slicing for
  Range responses no longer copies the underlying buffer; the
  cache stores a single backing allocation that 200 OK, 206
  Partial Content, and N concurrent readers all share.

### Tuning constants
Defined in `api/state.rs`, hardcoded for v0.39; promote to config
in a future release if production tuning demands it:
- `MEDIA_CACHE_TOTAL_BYTES = 256 MiB` — LRU total capacity
- `MEDIA_CACHE_ITEM_BYTES  = 16 MiB`  — per-item cache threshold
- `MEDIA_HANDLER_PERMITS   = 32`      — concurrent handlers

### Migration notes
- **No client-facing API changes.** Same endpoint, same response
  shape, same headers (now with `Content-Disposition` added).
- **Apache config from v0.38 still required** — the no-gzip
  directive for `/api/v1/media/` remains essential for Range
  semantics. The v0.38 rate-limit recommendation can be relaxed
  now that the in-node semaphore caps concurrency at 32, but
  keeping it doesn't hurt.

### Tests
Existing 34 `media_tests` plus 7 new `disposition_*` tests
covering the inline allowlist policy (41 total). The allowlist
tests are the load-bearing security regression — they lock
`image/svg+xml`, `text/html`, `application/javascript`, and
related dangerous types to `attachment`, preventing any future
detector addition from inadvertently promoting them to inline.

### Security hardening (audit-driven)
This release also addresses every actionable finding from the
v0.39 code + security audit pass:

- **CumulativeSize bug fixed.** `get_size` now calls
  `files/stat?offline=true` and returns the actual `Size` field,
  not `CumulativeSize`. The pre-fix path would emit
  `Content-Range: bytes start-end/<inflated-total>` with a body
  shorter than `end-start+1` — clients saw stalled or corrupt
  responses (audit critical C-1 security, warning W-3 code).
- **`If-None-Match` 304 short-circuit runs BEFORE the semaphore
  AND uses offline-only existence checks** (audit warnings W-1
  code / W-3 security). Pre-fix, a CDN periodically revalidating
  could saturate all 32 permits while making cheap probes that
  should not have required them; and an attacker spamming
  fabricated CIDs could pin Kubo into DHT walks. Both closed.
- **`media_cache` value now `CachedMedia { bytes, content_type }`**
  — cache hits skip both the IPFS fetch AND the
  `detect_content_type` re-sniff. The stream-range path's
  separate sniff fetch is unchanged but no longer affects cache
  hits (audit notes #5 code, N-2 security).
- **Cache-fill coalesced via `try_get_with`.** Concurrent cold-
  cache requests for the same CID now share a single IPFS fetch
  rather than each issuing their own (audit note N-4 security).
- **HEAD responses use the `(status, headers)` tuple form** (no
  body in tuple), guaranteeing the user-set `Content-Length`
  header is the only one emitted — no double-Content-Length
  smuggling risk (audit warning W-5 security).
- **`Content-Disposition` inline policy inverted from blacklist
  to allowlist** (audit warning W-4 security). The previous
  policy (anything-not-octet-stream → inline) would have
  auto-inlined any future detector addition; the new policy is
  an explicit MIME enumeration that requires opt-in for new
  types. Notably `image/svg+xml` is NOT inline — SVG's
  `<script>` execution would otherwise be a stored-XSS vector.
- **Stream-range slice length validated against requested
  length** — if Kubo returns a truncated range (e.g. due to an
  inflated stat), we respond with 502 Bad Gateway rather than
  200 + bogus `Content-Range` (audit critical C-1 security).
- **Sniff prefix fetch failure surfaces as 502** rather than
  silently flipping the disposition to `attachment` and breaking
  inline `<video>` playback for an otherwise-valid file (audit
  warning W-2 code).
- **`get_size` response capped at 8 KiB** to bound parser memory
  (audit note #6 code).
- **`exists_local` (offline-only stat) added to `IpfsClient`** as
  the building block for the safe-existence-probe path used in
  the 304 short-circuit.

## [0.38.0] - 2026-05-15

### Fixed
- **`GET /api/v1/media/:cid` now supports HTTP `Range:` requests.**
  Before this release every response was a single `200 OK` with the
  full file body and no `Accept-Ranges` header. That made any
  streaming-aware client (WebKitGTK `<video>`, VLC, mpv, ffplay,
  hls.js, …) unable to play MP4 files whose `moov` atom is positioned
  after `mdat` (the default for many encoders): the player needs to
  seek to the end of the file to read the metadata box before it can
  decode the data box, and a server that ignores Range makes that
  seek impossible. Result: VLC and the WebKit-embedded `<video>`
  element both errored with `mp4 stream error: no moov before mdat
  and the stream is not seekable`, even though the bitstream itself
  was perfectly valid. The handler now honours single-range requests
  per RFC 7233 (`bytes=START-END`, `bytes=START-`, `bytes=-SUFFIX`),
  returns `206 Partial Content` with proper `Content-Range` +
  `Content-Length`, advertises `Accept-Ranges: bytes` on every
  response (even the initial 200), and returns `416 Range Not
  Satisfiable` on malformed or out-of-bounds ranges. Multi-range
  requests (`bytes=0-99,200-299`) are not supported and fall through
  to 416 — clients then retry with single-range. 14 new unit tests
  in `media_tests` cover the parser.

- **`detect_content_type` now recognises video and audio containers.**
  Previously every non-image upload returned
  `application/octet-stream`, which caused WebKit's `<video>` element
  to refuse to even attempt decoding (the codec dispatcher reads
  Content-Type before touching the bitstream). The detector now
  identifies MP4/MOV/M4V/M4A (any `ftyp`-prefixed ISO Base Media file
  → `video/mp4`), WebM/MKV (EBML signature → `video/webm`), Ogg
  (`OggS` → `video/ogg`), AVI (`RIFF...AVI ` → `video/x-msvideo`),
  MP3 (ID3 tag or MPEG audio sync word → `audio/mpeg`), WAV
  (`RIFF...WAVE` → `audio/wav`), and FLAC (`fLaC` → `audio/flac`).
  Existing PNG/JPEG/GIF/WebP/PDF detection is preserved. 9 new
  detection tests in `media_tests`.

### Why these matter together
Either fix alone is insufficient. Without correct Content-Type the
browser/player rejects the file at codec-dispatch time; without Range
support the browser/player rejects it at demux time even when it
knows the type. Both must be in place for an MP4 with an end-of-file
`moov` atom (the typical encoder output) to play inline. With this
release the desktop app's `VideoAttachment` should play H.264 in
WebKitGTK directly (no "Open externally" fallback needed) on any
Linux system whose GStreamer stack has `avdec_h264` registered.

### Added (continued)
- **`Vary: Range` header on every media response.** Without this,
  intermediate caches (Apache `mod_cache`, Cloudflare, etc.) can
  cache a 206 Partial Content under the same key as a 200 full
  response, causing truncated bytes to be replayed to later
  clients. Cache-poisoning vector identified in audit, now closed.
- **`ETag: "<cid>"` + `If-None-Match` revalidation.** CIDs are
  content-addressed (the bytes for a CID never change), making them
  perfect strong validators per RFC 7232. Clients holding a fresh
  copy can probe with `If-None-Match: "<cid>"` and receive `304
  Not Modified` with no body — skips both the IPFS fetch and the
  full-body transfer.
- **`416 Range Not Satisfiable` response now includes
  `Accept-Ranges: bytes`.** Older VLC builds otherwise give up
  entirely on the first malformed-range response instead of
  retrying with a corrected single-range request. Per RFC 9110
  §15.5.17 recommendation.
- **Defensive `usize::try_from` on byte-range bounds before
  slicing.** No-op on 64-bit but guards correctness if anyone
  cross-compiles for armv7 / wasm32, where a u64 → usize cast
  would otherwise silently truncate and produce wrong slice bytes
  (content confusion, panic, or both).

### Deploy notes
- **Apache reverse-proxy operators MUST disable gzip for the media
  endpoint.** Range-byte semantics only work on the raw response
  bytes; if `mod_deflate` re-encodes the body, the `Content-Range`
  header's byte offsets no longer match what the client receives.
  Add the following to your vhost (or to a `Location` block
  scoped to `/api/v1/media/`):
  ```apache
  <Location /api/v1/media/>
      SetEnv no-gzip 1
      Header unset Content-Encoding
  </Location>
  ```
- **Recommended: rate-limit `/api/v1/media/` at the proxy until
  v0.39 ships.** See the security note below — until streaming
  IPFS lands, the handler is a candidate DoS vector under sustained
  load and should be throttled in front (e.g. `mod_ratelimit` /
  `mod_qos` on Apache, or a Cloudflare rate-limiting rule).

### Known security limitation (deferred — tracked for v0.39)
- **Memory-amplification DoS vector on the media handler.** The
  handler fetches the entire IPFS blob into memory before slicing
  it for the Range response. Under sustained load this is a
  candidate denial-of-service vector: ~200 concurrent clients
  rolling Range requests against a 50 MB asset peaks at ~20 GB
  transient RSS, more than enough to OOM-kill the node on most
  deployments. Mitigated for now by the proxy-layer rate limit
  above. Permanent fix in v0.39: switch to a streaming IPFS read
  (`/api/v0/cat?offset=&length=`) + bounded LRU cache for hot
  media + semaphore on concurrent handlers. This issue is not new
  to 0.38 — the pre-0.38 handler had the same full-blob fetch
  pattern — but the Range support makes per-request churn cheaper
  to trigger, so the proxy-level cap matters more now.

## [0.37.0] - 2026-05-15

### Fixed
- **Edits no longer destroy title, tags, attachments, or mentions on read.**
  Before this release `enrich_message_json` replaced the entire `payload`
  field with the edit's content string whenever a message was edited. For
  news posts that meant the title, tags, and attachments vanished from
  every subsequent read; for chat messages, attachments and mentions
  vanished too. The projection now decodes the original payload by
  `msg_type`, applies the edit's `content` plus any field-level overrides
  (`title`, `tags`, `attachments`) on top, and re-encodes as msgpack
  bytes — so clients see the same payload shape whether or not a message
  has been edited. Old envelopes without overrides still work: missing
  fields fall back to the original post's values.

### Added
- **Optional field-level overrides on `EditPayload` (spec §3.7).** The
  struct now carries `title: Option<String>`, `tags: Option<Vec<String>>`,
  and `attachments: Option<Vec<Attachment>>` in trailing positions with
  `#[serde(default)]`. msgpack wire-compat with pre-0.37 4-element edit
  envelopes is preserved — a dedicated test
  (`edit_payload_decodes_legacy_four_field_msgpack`) guards the
  contract. Validation caps mirror `validate_news_post`:
  `MAX_NEWS_TITLE`, `MAX_NEWS_TAGS` (+ `MAX_TAG_LENGTH` per tag),
  `MAX_ATTACHMENTS`. Per-type rules:
  - `NewsEdit` — all three fields applicable.
  - `ChatEdit` — only `attachments` accepted; `title`/`tags` rejected at
    validation so a misconfigured client fails loudly instead of
    silently being ignored.
  - `DirectMessageEdit` — all field overrides rejected (encrypted
    ciphertext blobs have no field-level shape from the server's view).

### Security
- Edit validation now enforces the same caps as the original post on any
  override fields a client supplies, closing a small inconsistency where
  a client could resend an arbitrarily large title in an edit envelope
  (the field was previously decoded but never validated, since the
  struct didn't carry it).

## [0.36.1] - 2026-05-14

### Fixed
- **Anchor count + status no longer cap at 200 lifetime anchors.**
  `get_self_anchor_status` (dashboard `total_anchors`) and
  `compute_anchor_status` (network-page `ANCHORED` column) both
  previously called `prefix_iter_cf(.., 200)`, which returned only the
  **oldest** 200 entries in the per-node anchor index. Once a node
  crossed 200 lifetime anchors, two cascading bugs appeared:
  - Dashboard's "total anchors" stuck at exactly 200 forever.
  - Network page's anchor-verified status went empty (`—`) because
    the function filtered the oldest-200 by `ts >= now - 7 days`, all
    of which were necessarily older than 7 days for any node with
    sustained anchoring → filtered set empty → returned
    `verified: false, level: "none"`.

  Replaced both with a full prefix scan (no limit, single forward
  pass). ANCHOR_BY_NODE is one row per anchor for the calling node
  only — bounded by anchoring frequency (~9k/year at default hourly
  anchoring), so a full scan is cheap. `iter.status()` is checked
  post-loop to surface RocksDB I/O errors. Counter accuracy and
  network-page status are now correct regardless of lifetime anchor
  count. Note: `last_anchor_age_seconds` was always correct — it
  comes from the `LAST_ANCHOR_TS` NODE_STATE counter, a separate
  code path written atomically by the StateAnchorer.

## [0.36.0] - 2026-05-13

### Added
- **Snapshot bootstrap — Phase 3 (anchor-verified, default-on).**
  Closes the security gaps deferred from v0.35 and flips bootstrap to
  default-on for fresh nodes:
  - **Klever anchor re-verification.** New
    `chain::anchor_verify::query_klever_state_root_at` queries the
    Ogmara KApp's `getStateRoot(block_height)` view (spec 02-onchain.md §745)
    per snapshot anchor. `snapshot_client::verify_anchors_against_klever`
    iterates `STATE_ANCHORS` rows top-down, finds the highest matching
    anchor, sets that as `cutoff_height`. Any mismatch = poisoned
    snapshot, hard abort. RPC failures retry up to half the anchor
    count before giving up.
  - **Producer Ed25519 signature verification.** New
    `producer_pubkey: Vec<u8>` field on `SnapshotManifest`
    (`#[serde(default)]` for back-compat). `verify_producer_signature`
    checks pubkey length (== 32), pubkey-to-node_id derivation, and
    Ed25519 signature over `canonical_signing_bytes`. v0.34/v0.35
    producers without the pubkey fall back to "quorum + Merkle +
    anchor verification only" with a clear warning, so a v0.36
    receiver can still bootstrap from upgrade-laggard peers.
    `canonical_signing_bytes` was extended to include the pubkey
    only when non-empty, preserving v0.34/v0.35 canonical signatures.
  - **Default-on bootstrap.** `snapshot.bootstrap_enabled` default
    flipped from `false` to `true`. Fresh nodes auto-fetch snapshots
    from peers. `bootstrap_only_if_fresh` (default true) still
    blocks the apply on non-fresh nodes.
  - **Automatic rollback dir GC.** New
    `chain::scanner::gc_snapshot_rollback_if_ready` runs after each
    block batch. Once `chain_cursor >= SNAPSHOT_APPLIED_AT_HEIGHT + 100`,
    the rollback checkpoint dir is `remove_dir_all`'d and both
    NODE_STATE sentinels are cleared. Best-effort — failure logs but
    doesn't break the scanner.
  - **`experimental_skip_anchor_verify` removed.** Phase 2's flag is
    gone; v0.36 always verifies anchors.
  - **11 new tests** — anchor chunk parse/sort, anchor verify outcome
    invariants, key/value height cross-check, signature verification
    round-trip + pubkey/node_id mismatch + tampered signature
    catches, validate rejects bad pubkey length, rollback GC
    early/ready/no-op cases. 85 total tests passing (was 73 in v0.35.0).
- **`SnapshotManifest::verify_producer_signature` + `SignatureCheck` enum.**
- **`chain::anchor_verify` module** with `query_klever_state_root_at`
  + `verify_anchor` returning a structured `AnchorVerifyOutcome` enum
  (`Match`/`Mismatch`/`NotAnchored`/`RpcError`).
- **Spec `docs/specs/11-snapshot-sync.md`**: new §5a.5 (Klever-verified
  cutoff), §5a.6 (producer signature), §5a.8 (rollback GC), §3.2/§3.4
  updates for `producer_pubkey`. `03-l2-node.md` §3.2.1 rewritten to
  describe the three-phase rollout.

### Changed
- `run_bootstrap` signature now takes `klever_node_url` and
  `contract_address` parameters; `experimental_skip_anchor_verify`
  parameter/field removed.
- `SnapshotManifest::canonical_signing_bytes` extended additively —
  Phase 1/2 signatures remain valid (pubkey appended only when present).
- `ogmara.example.toml` rewritten — bootstrap is documented as
  default-on with the verification chain explained inline.

### Security
- **Closes the Phase 2 audit's deferred items** (the two §5a.9 deferrals
  in v0.35's spec): producer signature verification AND Klever anchor
  re-verification are both now mandatory whenever the data is present.
- **Trust model in v0.36+:** ALL of (quorum agreement on snapshot_root)
  AND (Merkle re-computation from chunks) AND (per-anchor Klever
  re-verification) AND (producer Ed25519 signature, when available)
  must succeed. A peer-controlled attacker who can supply 3+ peers in
  the quorum still cannot apply a poisoned snapshot — every claimed
  anchor would have to also exist on the Klever chain with the same
  state_root, which requires compromising the producer's anchor wallet.
- Phase 1/2 producers (no `producer_pubkey`) fall back to "quorum +
  Merkle + anchor verification" — three independent defenses, only
  the signature backstop is missing. Receivers log a clear warning.

## [0.35.0] - 2026-05-13

### Added
- **Snapshot bootstrap — Phase 2 (opt-in client fetch + apply).** Joining
  nodes can now fetch the snapshot domain from existing peers and skip
  millions of Klever-block catch-up scans. The full pipeline:
  - **Discovery + quorum** — `select_quorum` groups `Advertise` responses
    by `(block_height, snapshot_root)`, requires ≥ `quorum_min_peers`
    (default 3) agreeing peers, ties broken by majority size then height.
    Pure logic, 7 unit tests cover threshold/tie-break/zero-height
    semantics.
  - **Manifest fetch + structural validation** — verifies `network_id`,
    `block_height`, `snapshot_root` match quorum, sums `total_bytes`
    against `max_total_bytes` (default 2 GiB), requires CFs match
    `DOMAIN_CFS` exactly in order.
  - **Parallel chunk fetch with retry** — `parallel_fetches` mirrors
    round-robin, per-chunk `chunk_retries` budget, hash-verify before
    decompress, `RateLimited`/`HeightMismatch` retry without consuming
    budget.
  - **Apply with rocksdb::Checkpoint rollback** — pre-apply Checkpoint
    captures the live DB (hard-linked, cheap), CFs cleared via
    `delete_range_cf`, chunks written via `WriteBatch`,
    `DEVICE_WALLET_MAP`+`WALLET_DEVICES` re-derived from `DELEGATIONS`
    via existing `backfill_delegation_map`, cursor+counters set,
    `SNAPSHOT_APPLIED_AT_HEIGHT` sentinel written last as the atomic
    commit point.
  - **8 new apply-path tests** against real tempdir RocksDB —
    `clear_cf` (empty + populated), `apply_snapshot_chunk` (write +
    cf-name guard), `create_checkpoint` (roundtrip + refuse-existing),
    full **end-to-end roundtrip** (source DB → build snapshot → wipe →
    apply to target → verify state matches), idempotent guard against
    double-apply at same height.
- **`SnapshotClientCommand` channel + correlation map** in
  `NetworkService`. The bootstrap orchestrator runs as its own task and
  dispatches outbound `SnapshotRequest`s through an mpsc channel; each
  outbound libp2p `OutboundRequestId` is stashed against a
  `oneshot::Sender`, and the snapshot event handler resolves the
  oneshot on `Message::Response` or `OutboundFailure`. Wrapped in
  `tokio::time::timeout` for per-request deadlines.
- **`Storage::clear_cf(cf_name)`** — RocksDB `delete_range_cf` over
  `[b"", &[0xff;256])` plus a tail-cleanup walk for keys ≥ the sentinel.
- **`Storage::apply_snapshot_chunk(cf, &ChunkPayload)`** — atomic
  WriteBatch of every `(key, value)` row; rejects cf-name mismatch.
- **`Storage::create_checkpoint(&Path)`** — wraps
  `rocksdb::checkpoint::Checkpoint`; refuses to overwrite existing dirs.
- **`schema::state_keys::SNAPSHOT_APPLIED_AT_HEIGHT`** + **`SNAPSHOT_ROLLBACK_DIR`**
  sentinels for apply pipeline crash recovery.
- **Expanded `SnapshotConfig`** — adds `bootstrap_only_if_fresh`,
  `experimental_skip_anchor_verify`, `allow_apply_over_existing`,
  `parallel_fetches`, `chunk_retries`, `discovery_timeout_secs`,
  `manifest_timeout_secs`, `chunk_timeout_secs`, `max_total_bytes`. All
  bootstrap flags default to safe-off; operators must explicitly opt in.
- **`tests/integration/SNAPSHOT_BOOTSTRAP.md`** — operator procedure for
  manual 3-node testnet verification while the automated harness is
  deferred to Phase 3.
- **Spec `docs/specs/11-snapshot-sync.md` §5a** — full Phase 2 client
  semantics: discovery, quorum, manifest validation, chunk fetch with
  retry, apply pipeline, cutoff semantics, crash recovery procedure.

### Changed
- `NetworkService::new` now takes a `SnapshotClientCommand` receiver.
- Phase 2 snapshot client is **opt-in**: BOTH `bootstrap_enabled = true`
  AND `experimental_skip_anchor_verify = true` must be set. Without the
  experimental flag the orchestrator logs a warn and falls back to scan
  — Phase 3 (v0.36) will remove the flag once anchor re-verification
  against Klever is wired.
- Node startup blocks the chain scanner spawn until the bootstrap task
  finishes (succeeds or falls back). Discovery has a configurable
  timeout (default 30s); on any failure path the scanner starts from
  the existing cursor as before.
- 34 snapshot-related tests now pass (was 15 in v0.34.0), 73 total.

### Security
The Phase 2 client passed parallel Code + Security audits. Findings
addressed before ship:
- **Merkle root recomputation after fetch.** Every received chunk's
  leaves are re-hashed into a chunk_root, cf_roots are recomputed from
  chunk_roots, and the snapshot_root is recomputed via
  `Storage::compute_snapshot_root`. Mismatch aborts the apply. Without
  this, a peer in the agreeing quorum could swap chunk contents for
  any values and only need a matching `chunk_hash` in the manifest —
  the per-chunk hash check by itself was therefore meaningless. New
  `verify_merkle_consistency` function is the most important defense
  added.
- **Boot-time crash recovery.** `check_snapshot_apply_recovery` runs
  before any read/write. If `SNAPSHOT_ROLLBACK_DIR` is set but the
  success sentinel is absent → restore from rollback automatically:
  rename the corrupt DB aside, promote the checkpoint, clear the
  marker. If the rollback dir was manually deleted, refuse to boot
  with a clear error.
- **Per-row JSON validation during apply.** Every row in JSON-valued
  CFs (USERS, CHANNELS, CHANNEL_MEMBERS, DELEGATIONS, STATE_ANCHORS)
  must parse as valid JSON or the apply aborts atomically before any
  destructive op. Closes the "malicious peer plants malformed values
  → persistent API DoS" vector.
- **Anchor height bounds.** Manifests with
  `last_verified_anchor_height > block_height` or `== 0` are rejected.
  The latter blocks unanchored snapshots outright; the former would
  let a malicious primary advance `chain_cursor` past the tip.
- **Stricter fresh-node gate.** "Fresh" is now `cursor == 0` only,
  not `cursor < start_block`. The earlier formulation could let a
  high `start_block` config slip the destructive apply past an
  existing healthy node's state.
- **Quorum split-brain detection.** If two equally-sized groups tie on
  block_height but disagree on `snapshot_root`, `select_quorum`
  returns `None` instead of letting `HashMap::into_iter` ordering
  decide which fork to follow.
- **Bounded `pending_snapshot_requests` map** (8192 cap) with
  opportunistic GC of dropped receivers each send. Caps the per-session
  memory of a peer-churn attack.
- **Spec §5a.7 + §5a.8 explicitly document deferred items:** producer
  signature verification ships in Phase 3 (currently only length is
  checked), and sybil resistance relies on `bootstrap_nodes` being
  trusted. The release-note language is unambiguous that Phase 2 is
  an experimental opt-in with a quorum-based trust model.

## [0.34.0] - 2026-05-12

### Added
- **Snapshot bootstrap — Phase 1 (serve-only).** New `[snapshot]` config
  section and `/ogmara/{net}/snapshot/1.0.0` libp2p request-response
  protocol let v0.34+ nodes cache a Merkle-rooted summary of their
  SC-derived state (users, channels, channel_members, delegations,
  state_anchors, anchor_by_node) and serve it to peers. `device_wallet_map`
  and `wallet_devices` are deliberately excluded — Phase 2 receivers
  re-derive them from `delegations` rather than exposing wallet↔device
  linkages in bulk to any peer. Once Phase 2 ships in v0.35, joining nodes will be
  able to bootstrap from these caches instead of replaying millions of
  Klever blocks. See `docs/specs/11-snapshot-sync.md` for the full
  format, including the three-level Merkle hashing scheme, signed
  manifests, and forward-compatibility plan.
  - **Cache builder.** A background task rebuilds the cached snapshot
    every `serve_rebuild_interval_secs` (default 3600s). Chunks target
    4 MiB uncompressed, are MessagePack-serialized, then zstd-3
    compressed. The first build is intentionally deferred 60s after
    startup so it doesn't block boot.
  - **Manifest signing.** Producers sign the canonical manifest bytes
    with their Ed25519 node identity key. Receivers in Phase 2 will
    verify against the libp2p PeerId-derived public key.
  - **`GET /admin/snapshot/status`.** New admin endpoint surfaces the
    current cache: block height, snapshot root, per-CF entry counts and
    Merkle roots, compressed total bytes, and the producer node ID.
  - **`NodeAnnouncementPayload` gains optional `snapshot_height` /
    `snapshot_root` fields.** Older nodes ignore the new fields via
    `#[serde(default)]` — backwards-compatible additive change.
  - **`Capability::SnapshotServe` is implicit:** rather than extending
    the `Capability` enum (which would break old `serde(repr(u8))`
    decoders), peers infer snapshot-serving from the presence of
    `snapshot_height` in the announcement.
  - Adds `zstd = "0.13"` dependency for chunk compression.
- **`crypto::merkle::hash_kv(key, value)`** — domain-separated leaf hash
  for `(key, value)` pairs. Used by snapshot Merkle trees so that
  `("a", "bc")` and `("ab", "c")` cannot collide.
- **`storage::snapshot` module** — the wire-shared `ChunkHeader`,
  `ChunkPayload`, `CfManifest`, and `BuiltCf` types plus
  `finish_chunk` / `decode_chunk` helpers. 10 new unit tests cover the
  round-trip and tampering detection paths.
- **`Storage::build_snapshot_cf` and `Storage::compute_snapshot_root`**
  produce the per-CF chunks and the overall snapshot root, respectively.
- **`schema::snapshot::DOMAIN_CFS` constant** — canonical ordering of
  the column families covered by a snapshot. Changing the order is a
  manifest-version-bumping wire break.

### Changed
- `src/network/behaviour.rs` adds a second `request_response::cbor::Behaviour`
  for the snapshot protocol. Per-request timeout is 60s (vs. 30s for sync) to
  accommodate larger chunk responses. When `snapshot.serve_enabled = false`,
  the protocol registers as `Outbound`-only so the node still negotiates the
  protocol string for future Phase 2 client requests but doesn't accept
  inbound serve requests.
- `NetworkService::new` now takes a `SharedSnapshotCache` handle. `AppState`
  carries the same handle so the admin endpoint can read it without going
  through the network layer. Default-constructed (test) AppStates pass an
  empty cache.
- Spec `docs/specs/03-l2-node.md` §3.2.1 cross-references the new spec.

## [0.33.1] - 2026-05-12

### Changed
- **Admin dashboard — "Recent Rejections" table now shows full date + time.**
  Previously the Time column only rendered `toLocaleTimeString()`, which made
  it impossible to tell whether a rejection happened today or last week.
  The cell now uses `toLocaleString()` (locale-formatted date + time) and a
  `title` tooltip with the full ISO-8601 timestamp for millisecond-precise
  inspection. Header relabeled `Time` → `Date / Time`. No API changes —
  the existing `/admin/metrics/rejections` payload already carried a
  millisecond `timestamp` field; only the dashboard renderer changed.

## [0.33.0] - 2026-05-12

### Added
- **Per-channel mention counts in `GET /api/v1/channels/unread`.**
  Response now includes a `mentions` map alongside `unread`:
  `{ "unread": { "1": 5 }, "mentions": { "1": 2 } }`. For each unread
  message, the payload is MessagePack-decoded and its `mentions[]`
  array is scanned for the viewer's wallet address (resolved through
  delegation, so device-key mentions count too). Counts are capped at
  99 like `unread`. Only channels with `mention_count > 0` appear in
  the map. Older clients that ignore the new field continue to work
  unchanged. Lets clients show a per-channel `@` indicator in the
  sidebar so users see *where* they were pinged at a glance.
- Spec `docs/specs/03-l2-node.md` §unread updated to document the new field.

## [0.32.0] - 2026-05-06

### Added
- **`@`-mention autocomplete endpoint (`GET /api/v1/users/search`).**
  Implements protocol spec §3.3 and L2 spec §4.1. Case-insensitive
  prefix search on `display_name` returns up to 50 results with
  `{ address, display_name, avatar_cid, verified }` per match. The
  `verified` flag is `true` for on-chain-registered users
  (`registered_at > 0`). No authentication required — display names
  are already public profile data.
  - Address-prefix matches: when the query starts with `klv1`, results
    also include any address with that prefix from USERS, so users
    can complete `@klv1abc...` without a display name set.
  - Validation: `q` is required, 1..=64 chars after trim; `limit` is
    clamped to 1..=50 (default 20). Empty/missing q returns 400.
- **`USERS_BY_NAME` column family** — case-insensitive prefix index
  keyed by `lowercase(display_name) + 0x00 + klever_address`. The
  null separator is below printable ASCII so prefix scans of the
  lowercased name match every entry without leaking into the address
  suffix. Maintained in lockstep with USERS on every `ProfileUpdate`
  (delete old name's row, insert new name's row).
- **One-time migration `backfill_users_by_name`** — runs on first
  startup after v0.32.0, scans existing USERS records and writes index
  entries for every user with a non-empty display name. Protected by
  the `USERS_BY_NAME_BACKFILLED` sentinel in `NODE_STATE` so it runs
  exactly once. Without this, only post-upgrade `ProfileUpdate` events
  would populate the index, leaving long-time users invisible to
  autocomplete.
- 4 new schema tests covering the index key encoding/decoding,
  lexicographic prefix-scan ordering, and the separator's position
  relative to the `klv1` prefix. Total tests: 35 → 39.

### Notes
- The chain scanner's `UserRegistered` handler doesn't need updating —
  it preserves the existing `display_name` field on re-registration,
  so any index row created by an earlier `ProfileUpdate` survives.
  New on-chain registrations with no prior profile have no display
  name and therefore no index row, which is correct.
- `display_name` collisions are allowed: two users named "alice" both
  appear in autocomplete and the client disambiguates by address.
  This is consistent with the "no global username uniqueness" decision
  in the original Phase 2 plan.

## [0.31.0] - 2026-05-04

### Added
- **Read-only / broadcast channel enforcement (protocol spec §3.6, L2 spec §3.4
  step 7e).** When a channel's runtime `channel_type` is `ReadPublic` (1), the
  router now rejects `ChatMessage`, `ChatEdit`, and `ChatDelete` envelopes
  whose resolved author is neither the channel creator nor a moderator.
  `ChatReaction` is intentionally unaffected so members can still react.
  Rejection surfaces as `broadcast_channel_post_denied` in the route result.
  The check reads the L2 channel record (not the on-chain immutable
  `channel_type`) so creators can flip broadcast mode at runtime.

- **Runtime channel-type toggle via `ChannelUpdate`.** `ChannelUpdatePayload`
  gained an optional `channel_type` field. Creators and moderators with
  `can_edit_info` may flip a channel between `Public` and `ReadPublic` by
  publishing a signed `ChannelUpdate` envelope. Switching to or from
  `Private` is refused (the storage and discovery model differs and cannot
  be retrofitted post-creation); refused flips are logged via `warn!` and
  silently dropped from the merge — every other field in the same envelope
  still applies.

- **Threaded mode toggle (`threads_enabled`).** `ChannelUpdatePayload` also
  gained an optional `threads_enabled: bool` flag persisted on the L2
  channel record. The flag is a pure rendering/pagination hint — no
  structural migration is performed and no router enforcement is wired
  against it yet (Phase 3 will land the indexing CFs and thread endpoints).
  Existing chat messages remain readable in either mode.

### Changed
- **Atomic ChannelUpdate semantics for refused type flips.** A
  `ChannelUpdate` envelope that requests a flip to `Private` is now refused
  at validation (`validate_channel_update`) rather than silently dropping
  the `channel_type` field while applying sibling fields (display_name,
  description, etc.). Clients receive a clear rejection ("channel_type
  cannot be flipped to Private post-creation") instead of a misleading
  partial-success. The exotic "flip away from Private" case is still guarded
  inside the merge handler (validation cannot see the current channel state).
- **Removed redundant CHANNELS read in read-only enforcement.** The
  `check_readonly_channel` step now reuses the JSON value already loaded for
  the channel-type lookup to derive `creator`, eliminating a second
  `get_cf` call per chat write and closing a TOCTOU window where a deleted
  channel record between reads could surface an error to the caller.

### Notes
- API responses already include the L2 channel JSON verbatim, so
  `channel_type` and `threads_enabled` surface immediately in
  `GET /api/v1/channels` and `GET /api/v1/channels/{id}` without further
  changes. Clients should treat the L2 value as authoritative for runtime
  posting policy (per protocol spec §3.6).
- 6 new validation tests cover the channel_type flip matrix (Public,
  ReadPublic, Private rejection, atomic-reject with sibling fields, and
  the threads_enabled toggle). All 35 in-repo tests pass.

### Known follow-ups (not blockers for this release)
- Read-only enforcement adds an unconditional `CHANNELS` lookup and JSON
  parse on every `ChatMessage`/`ChatEdit`/`ChatDelete`. RocksDB block cache
  absorbs this under steady state, but a future pass should memoize
  `(channel_id → channel_type, creator)` in a small `DashMap` invalidated
  on `ChannelUpdate` to drop the JSON parse cost from the hot path.
- `ChannelType` is `#[repr(u8)]` but lacks `serde_repr` — the wire format
  is the variant name string, while storage uses the numeric discriminant.
  This works correctly today but is a footgun if a future change ever
  expects numeric wire format.
- Mods with `can_edit_info` can flip `channel_type` (Public ⇄ ReadPublic),
  not just creators. Per spec §3.6 this is intentional, but worth confirming
  product-side; tightening to creator-only is a one-line change in
  `authorize_channel_action`.

## [0.30.5] - 2026-05-02

### Fixed
- **Chain scanner overwrote L2-only channel fields** — both `ChannelCreated`
  and `ChannelTransferred` event handlers rebuilt the `CHANNELS[id]` row from
  a struct that only knew `display_name`, `description`, `member_count`.
  Fields written by L2 `ChannelUpdate` envelopes (`logo_cid`, `banner_cid`,
  `website_url`, `tags`) were silently dropped on every overwrite. Symptom:
  public channel avatars and banners disappeared after node restart, chain
  re-scan, or any on-chain event that re-emitted `ChannelCreated` /
  `ChannelTransferred`. Private channels were unaffected because they have
  no on-chain footprint.

  Both handlers now JSON-merge into the existing record instead of struct-
  serializing — only the on-chain authoritative fields are overwritten
  (`channel_id`, `slug`, `creator`, `channel_type`, `created_at` for
  ChannelCreated; `creator` for ChannelTransferred), every other field
  survives intact. New channels still get the canonical `ChannelRecord`
  skeleton on first sight. Future L2-only fields are preserved automatically
  without requiring scanner changes. Corrupted-JSON and non-object record
  shapes are now logged via `tracing::warn!`/`error!` instead of silently
  swallowed or aborting the entire scan tick.

## [0.30.4] - 2026-04-11

### Fixed
- **Device registration 500 on corrupted entries** — `list_devices` fails to
  deserialize pre-v0.15 device claims (JSON/MessagePack format mismatch),
  causing a 500 that permanently blocks wallet connection. Now logs a warning
  and proceeds with registration instead of crashing. The new valid device
  claim overwrites the corrupted data.

## [0.30.3] - 2026-04-11

### Fixed
- **PoW challenge response includes resolved address** — the 429 `pow_required`
  response now includes an `address` field with the exact resolved author
  address the challenge was issued for. This lets the SDK submit the correct
  address without guessing, fixing mismatches when device registration hasn't
  completed yet.
- Added detailed debug logging for auth signature failures (temporary diagnostic).

## [0.30.2] - 2026-04-11

### Fixed
- **`export-key` and `identity` work while node is running** — these commands
  used `Node::init()` which requires a write lock on RocksDB, failing with
  "Resource temporarily unavailable" when the node process holds the lock.
  Now uses a read-only RocksDB open (`open_cf_descriptors_read_only`) that
  coexists with the running node's write lock.

## [0.30.1] - 2026-04-11

### Fixed
- **Config file auto-discovery** — all subcommands (`run`, `identity`, `export-key`,
  `import-key`) now auto-detect the config file at common locations
  (`/etc/ogmara/ogmara.toml`, `/etc/ogmara-node/ogmara.toml`) if the default
  `ogmara.toml` doesn't exist in the current directory. Previously, running
  `ogmara-node export-key` on a server failed with "No such file" because the
  config was in `/etc/ogmara/` but the command expected `./ogmara.toml`.

## [0.30.0] - 2026-04-11

### Added
- **`ogmara-node export-key`** — exports the node's Ed25519 private key to a file
  for backup. Includes address and node ID in comments, sets 0600 permissions.
  Prevents fund loss when the data directory is deleted or migrated.
- **`ogmara-node import-key`** — imports a previously exported key into the node's
  database. Restores the node's identity (wallet address, peer ID) after a data
  wipe, server migration, or disaster recovery.
- **Startup wallet address log** — the node now logs its Klever wallet address at
  startup with a reminder to back up the key.

### Changed
- **Documentation warnings** — all docs mentioning `rm -rf data` now include
  prominent warnings about private key loss and instructions to `export-key` first.
  Updated 03-l2-node.md spec and BUILDING.md.

## [0.29.2] - 2026-04-11

### Added
- **`klever.start_block` config** — skip blocks before the SC deployment on first
  sync. Only used when the chain cursor is 0 (fresh node). Prevents scanning
  millions of irrelevant blocks. Mainnet SC deployed at block 29,686,185 —
  without this, a fresh node would scan from block 1.

## [0.29.1] - 2026-04-11

### Added
- **Node wallet in dashboard** — Overview tab shows the node's Klever wallet address
  and KLV balance. Balance fetched from Klever API every 60 seconds. Color-coded:
  green (>50 KLV), yellow (10-50 KLV), red (<10 KLV) to warn node operators when
  the anchoring wallet needs funding.

## [0.29.0] - 2026-04-11

### Added
- **Network isolation between testnet and mainnet** — nodes on different Klever
  networks now refuse to peer with each other. All libp2p protocol identifiers
  (Identify, Kademlia, Sync, GossipSub topics) include the network name
  (`mainnet` or `testnet`), so cross-network connections are rejected at the
  protocol-negotiation level. The `network.network_id` config field is
  auto-detected from `klever.node_url` if not explicitly set. This prevents
  data corruption from mixed-network syncing and channel ID collisions.

### Security
- **Cross-network peering vulnerability** — prior to this version, a testnet
  node and a mainnet node could discover, connect, and sync messages with each
  other because all protocol IDs and topic names were identical across networks.
  This could cause channel ID collisions and data corruption.

## [0.28.3] - 2026-04-11

### Changed
- **User profile endpoint returns empty profile instead of 404** — `GET /api/v1/users/:address`
  now returns a minimal profile object (`address`, `follower_count`, `following_count`) for
  addresses without a stored profile, instead of `404 user not found`. This avoids noisy
  console errors on web/desktop clients when displaying messages from users who haven't set
  up a profile yet.

## [0.28.2] - 2026-04-11

### Fixed
- **Anchor status always "none"** — `compute_anchor_status()` and `get_self_anchor_status()`
  used milliseconds for `now` but Klever TX timestamps stored in ANCHOR_BY_NODE keys are
  in unix seconds. The seconds-vs-milliseconds mismatch caused every timestamp comparison
  to fail, making all nodes show `level: "none"` regardless of actual anchoring activity.
  Both functions now use `as_secs()` consistently.

## [0.28.1] - 2026-04-11

### Fixed
- **PEER_DIRECTORY key collision** — persisted peer addresses and NodeAnnouncement
  entries shared the same CF without key prefixes. Peer addresses now use `pa:` prefix
  (`pa:{peer_id}` → multiaddr). Prevents cross-contamination where `dial_persisted_peers`
  tried to parse JSON announcements as multiaddrs, and `/network/nodes` tried to parse
  multiaddrs as JSON.
- **Unbounded peer address writes** — `persist_peer_addr()` now caps at 256 stored
  entries. Previously every Identify event wrote to storage with no limit.
- **O(n) reconnect queue eviction** — `remove(0)` replaced with `swap_remove(0)` for
  O(1) performance when the 128-entry queue is full.

## [0.28.0] - 2026-04-11

### Added
- **Persistent peer storage** — when an Ogmara peer is identified via the Identify
  protocol, its multiaddr is persisted to the `PEER_DIRECTORY` RocksDB column family.
  On startup, the node dials all stored peers (up to 64) alongside bootstrap nodes.
  This eliminates the single point of failure: if all bootstrap nodes are down, the
  node can still rejoin the network using previously-connected peers.
- **Stale peer cleanup** — when reconnection attempts are exhausted (10 attempts),
  the peer is removed from both in-memory cache and persistent storage.

## [0.27.4] - 2026-04-11

### Fixed
- **Empty bootstrap_nodes auto-populated on startup** — existing configs with
  `bootstrap_nodes = []` (from pre-v0.27.2) now get the official bootstrap nodes
  injected at load time via a config migration. Logged as "Config migration: adding
  default bootstrap nodes". No manual config editing required for upgrades.

## [0.27.3] - 2026-04-11

### Fixed
- **DNS bootstrap nodes couldn't resolve** — the libp2p swarm was built without
  the DNS transport (`.with_dns()`), so `/dns4/node.ogmara.org/...` multiaddrs
  silently failed to dial. Added `dns` feature to libp2p and `.with_dns()` to
  the swarm builder. This was the root cause of new nodes not connecting to the
  network even with bootstrap nodes configured.
- **Bootstrap redial errors invisible** — dial failures were logged at `debug`
  level, invisible at default `info` log level. Upgraded to `warn`/`info`.

## [0.27.2] - 2026-04-11

### Added
- **Default bootstrap nodes** — `ogmara-node init` now generates config with the
  official Ogmara bootstrap node (`node.ogmara.org`) pre-configured for both TCP
  and QUIC transports. New node operators no longer need to manually find and add
  bootstrap peers — the node connects to the network automatically on first start.
  Uses DNS-based multiaddrs (`/dns4/`) so the config survives IP changes.
- **Bootstrap nodes in struct default** — if `bootstrap_nodes` is omitted from
  `ogmara.toml`, the official nodes are used automatically via `serde(default)`.

## [0.27.1] - 2026-04-11

### Fixed
- **Unbounded reconnect queue** — capped at 128 entries, evicts oldest when full.
  Prevents memory growth from mass disconnection events.
- **Unbounded known_peer_addrs** — capped at 2048 entries. Addresses are cleaned up
  when reconnection attempts are exhausted (max 10 attempts).

## [0.27.0] - 2026-04-11

### Fixed
- **Peer reconnection deadlock** — nodes could not reconnect after restart because
  Kademlia bootstrap was skipped when `peer_count == 0`, creating a deadlock: can't
  find peers without bootstrap, can't bootstrap without peers. Now always attempts
  Kademlia bootstrap and redials configured bootstrap nodes when peer count is zero.
- **No reconnection on peer disconnect** — when a peer disconnected, the node forgot
  about it entirely with no retry. Now queues disconnected peers for reconnection with
  exponential backoff (5s base, doubling up to 5 min, max 10 attempts).
- **Idle connection timeout too aggressive** — was 60 seconds, causing peers to
  disconnect during quiet periods. Increased to 5 minutes.
- **Non-Ogmara peers polluted DHT** — Identify results from non-Ogmara peers were
  added to the Kademlia routing table, wasting queries. Now only adds peers whose
  protocol version starts with `/ogmara/`.
- **GossipSub Unsubscribed event ignored** — peer unsubscriptions were silently
  swallowed. Now logged for mesh debugging.
- **GossipsubNotSupported event ignored** — peers that don't support GossipSub were
  silently accepted. Now logged for protocol compatibility tracking.

### Added
- **Peer reconnection with exponential backoff** — `ReconnectEntry` queue processes
  every 10 seconds. Disconnected Ogmara peers are redialed with 5s→10s→20s→...→5min
  backoff, up to 10 attempts. Successfully reconnected peers are removed from queue.
- **Known peer address tracking** — stores the first listen address from Identify
  for each peer. Used for reconnection after disconnect.
- **Periodic bootstrap node redial** — every 30 seconds, if peer count is zero,
  actively redials all configured bootstrap nodes. Previously only dialed once at
  startup.
- **Per-peer connection limit** — max 2 connections per peer to prevent a single
  peer from exhausting the inbound connection limit.

## [0.26.1] - 2026-04-11

### Added
- **PoW counter in dashboard** — Messages tab now shows "PoW Required" count
  separately from "Rejected". Previously PoW rejections were uncounted.
- **Recent rejections log** — Messages tab shows the last 20 rejection reasons
  with timestamps and author addresses. Helps node operators diagnose why messages
  are failing (signature errors, timestamp drift, PoW required, payload validation).
- **`GET /admin/metrics/rejections`** — REST endpoint returning last 50 rejections
  with reason, author, and timestamp.

### Fixed
- **"Failed Signatures" renamed to "Rejected"** — the counter tracks ALL rejection
  reasons (signature, timestamp, rate limit, payload), not just signature failures.
  The old label was misleading.

## [0.26.0] - 2026-04-10

### Added
- **IP rate limiting** — per-IP request throttling via `governor` crate middleware.
  Configured via `api.rate_limit_per_ip` (default: 100 req/min). Previously this
  config value existed but was deliberately ignored (`_rate_limit_per_minute`).
- **Proof-of-Work anti-spam** — new wallets must solve a SHA-256 hash puzzle
  (~2-3 seconds) before their first message is accepted. On-chain registered
  wallets and wallets that have previously solved a challenge are exempt.
  Configurable via `[api.pow]` section (difficulty, TTL, enable/disable).
- **Known wallets persistence** — new `KNOWN_WALLETS` RocksDB column family
  stores wallets that have solved PoW or are on-chain registered. Survives
  node restarts (unlike in-memory rate limit counters).
- **PoW API endpoints** — `POST /api/v1/pow/challenge` and
  `POST /api/v1/pow/verify` for requesting and submitting PoW solutions.
- **Background cleanup task** — periodic eviction (every 5 min) of stale
  per-user rate limit entries and expired PoW challenges.

### Fixed
- Rate limit entries now cleaned up periodically. Previously
  `cleanup_rate_limits()` existed but was never called, causing unbounded
  memory growth.

### Security
- Mitigates Sybil spam attacks via key rotation. Each new wallet identity
  now requires ~2-3 seconds of CPU work before posting, making mass identity
  creation impractical (1000 wallets = ~30-40 min CPU time).
- IP-based rate limiting prevents HTTP-level DoS from single sources.

## [0.25.2] - 2026-04-10

### Fixed
- **Messages card showed total envelopes, not chat messages** — the "Messages"
  card on the Overview tab was showing `TOTAL_MESSAGES` which includes ALL
  envelope types (chat, news, profiles, channel events, delegations, etc.).
  Now shows `channel_messages_total` (actual chat messages) as the primary
  number, with news count and total envelopes as a label below.

### Added
- **Message type breakdown** in WebSocket payload — `channel_messages_total`
  and `news_messages_total` fields added alongside `messages_total`.

## [0.25.1] - 2026-04-10

### Security
- **Challenge nonce failures now return errors** — previously, if the mutex was
  poisoned or the 100-nonce limit was reached, the server returned a nonce that
  could never be consumed (silent failure). Now returns HTTP 503 with an error
  message. Prevents DoS via challenge pool exhaustion.
- **Cookie parse errors handled** — `cookie.parse().unwrap()` replaced with
  graceful error handling to prevent panics on malformed session tokens.
- **Atomic WebSocket connection limit** — the check-and-increment was a non-atomic
  load+compare that could exceed the 10-connection limit under concurrency. Now
  uses `fetch_update` for a single atomic operation.
- **Mutex poison logged on challenge consume** — poisoned mutex during nonce
  consumption now logs a warning instead of silently returning None.

## [0.25.0] - 2026-04-10

### Added
- **Chain sync lag** — chain scanner now stores the chain tip height in NODE_STATE
  on every poll cycle. Dashboard computes real `sync_lag_blocks` as `chain_tip -
  last_indexed_block` instead of hardcoded 0.
- **Alert history endpoint** — `GET /admin/alerts/history` returns the last 100
  alerts from the shared AlertEngine history (severity, condition, message, timestamp).
- **Alerts tab wired** — loads alert history from the REST endpoint with severity
  color coding. Shows "No alerts recorded" when alerts are disabled.
- **Alert banner wired** — top-of-page banner now shows the latest unresolved alert
  from the history endpoint. Previously was dead HTML that never triggered.
- **History ring buffer charts** — Network, Storage, and Messages tabs now fetch
  real 1-minute resolution data from `GET /admin/metrics/history` instead of relying
  solely on the 2-second in-browser sparkline buffer. Charts show actual last-hour
  data from the server's ring buffer.

### Fixed
- **Klever health dot** — now turns yellow when sync lag exceeds 100 blocks (was
  only checking if any block was ever indexed).
- **Anchoring health dot** — now turns yellow when last anchor age exceeds 2 hours
  (was only checking if any anchor existed, regardless of recency).

## [0.24.9] - 2026-04-10

### Fixed
- **Message counters were always zero** — counters were only wired into the GossipSub
  handler. Messages from REST API (`POST /api/v1/messages`) and sync protocol were
  not counted. Added counter increments to `post_message` route handler (received,
  stored, failed) and sync response handler (received, stored, failed per message).

## [0.24.8] - 2026-04-10

### Fixed
- **Storage tab disk chart was empty** — the `chart-disk` container existed but
  was never rendered into. Added disk usage data to sparkline collection and
  wired `lineChart()` call when the Storage tab is active.

## [0.24.7] - 2026-04-10

### Fixed
- **Anchor count was inflated** — used RocksDB `estimate-num-keys` which grows
  with each flush/compaction. Now uses `get_self_anchor_status()` which accurately
  counts this node's anchors from the `ANCHOR_BY_NODE` column family.

### Added
- **Ogmara favicon** — embedded the official purple-blue monogram "O" SVG favicon
  as an inline data URI in the dashboard page.

## [0.24.6] - 2026-04-10

### Fixed
- **Line charts no longer stretched** — charts now use the container's actual pixel
  dimensions instead of a fixed viewBox with `preserveAspectRatio="none"`, which
  was causing extreme horizontal stretching on wide screens.
- **Y-axis labels on zero-value charts** — when all values are 0, the axis showed
  "1,1,1,0,0" (rounded integers from a 0-1 range). Now uses smart formatting
  (decimal places based on value range) and anchors Y-axis at 0 when appropriate.

## [0.24.5] - 2026-04-10

### Fixed
- **Klever block number shows full value** — was shortened via `fmt()` (e.g., "9.2M"),
  now displays with locale formatting (e.g., "9,220,119").

## [0.24.4] - 2026-04-10

### Fixed
- **Klever Extension detection** — was only checking `window.klever` (K5 mobile),
  now checks both `window.kleverWeb` (desktop extension) and `window.klever`.
  Desktop extension requires `initialize()` before `getWalletAddress()`. Message
  signing tries `window.klever.signMessage` first, then `window.kleverWeb.signMessage`
  as fallback. Matches the patterns used in the web and desktop apps.

## [0.24.3] - 2026-04-10

### Fixed
- **Dashboard page loads without auth** — the HTML page was behind the auth
  middleware, returning "authentication required" before the login UI could
  render. Moved `/admin/dashboard` to the public route group alongside the
  auth endpoints. Data endpoints (metrics, WebSocket) remain protected.

## [0.24.2] - 2026-04-10

### Fixed
- **Admin auth middleware Extension ordering** — the `AdminAuthState` extension
  layer was added inside the middleware layer, making it unavailable when the
  middleware ran. Swapped layer order so Extension is outermost (available first).

## [0.24.1] - 2026-04-10

### Fixed
- **Reverse proxy support for admin auth** — the localhost bypass now checks
  `X-Forwarded-For` header when the TCP peer is loopback. Without this, all
  requests through Apache/nginx appeared as localhost and bypassed auth entirely.
  Only trusts the header when TCP peer is `127.0.0.1` (prevents spoofing from
  remote clients).
- **Cookie path changed from `/admin` to `/`** — ensures the session cookie is
  sent for auth endpoint requests at `/admin/auth/*` which were outside the
  previous path scope.
- **Cookie SameSite changed from Strict to Lax** — Strict blocks the cookie on
  initial navigation from external links (e.g., bookmarks). Lax allows it.
- **Added Secure flag to session cookies** — ensures cookies are only sent over
  HTTPS in production.

## [0.24.0] - 2026-04-10

### Added
- **Wallet-based dashboard authentication** — challenge-response login using Klever
  wallet signatures (spec 10-dashboard.md §5). Flow: GET `/admin/auth/challenge` →
  sign with Klever Extension → POST `/admin/auth/login` → HMAC-signed session token.
  Enables remote dashboard access for wallets listed in `admin_wallets` config.
- **Login page in dashboard UI** — "Connect Wallet" button integrates with Klever
  Extension (`window.klever.signMessage`). Shows wallet address on success, logout
  button clears session. Localhost access remains auth-free (bypass preserved).
- **Session tokens** — HMAC-SHA256 signed, HttpOnly cookie + Bearer header support,
  configurable TTL (default 24h), invalidated on node restart (new HMAC secret).
- **Admin auth middleware** — replaces `localhost_only`. Passes localhost requests
  without auth, validates session token for remote requests, rejects if no
  `admin_wallets` configured.
- **`/admin/auth/challenge`** — generates 32-byte random nonce with 5-minute TTL.
- **`/admin/auth/login`** — verifies nonce, wallet address against admin list,
  Klever message signature, issues session token + cookie.
- **`/admin/auth/logout`** — clears session cookie.

### Security
- Nonces are single-use and TTL-bounded (5 min, max 100 pending).
- Session tokens use constant-time comparison to prevent timing attacks.
- Challenge nonces pruned on every new challenge request.
- WebSocket connection limit (max 10) prevents local DoS.
- Secret config fields (`bot_token`, `webhook_url`, `auth_token`) marked
  `skip_serializing` with redacted `Debug` impl — never leak via logs or serialization.

## [0.23.0] - 2026-04-09

### Added
- **Node operator dashboard** — complete multi-section SPA served at `/admin/dashboard`
  with real-time metrics via WebSocket (2s push). Sections: Overview (health indicators,
  metric cards with sparklines), Network (peers table, bandwidth charts), Storage
  (RocksDB column family breakdown, IPFS stats), Messages (throughput charts, counters),
  Alerts (status display). Dark theme default with light toggle. Vanilla HTML/CSS/JS,
  inline SVG charts, zero external dependencies. (spec 10-dashboard.md)
- **Metrics collection infrastructure** — background `MetricsCollector` task sampling
  CPU/memory/disk via `sysinfo` crate, network counters via shared atomics, storage
  stats via RocksDB properties, IPFS stats via HTTP API. 24-hour ring buffer at
  1-minute resolution (~280 KB memory).
- **New admin REST endpoints** — `GET /admin/metrics/snapshot` (full current metrics),
  `GET /admin/metrics/history` (time-series from ring buffer), `GET /admin/metrics/peers`
  (detailed peer table), `GET /admin/metrics/storage` (column family breakdown).
- **Network counters** — `NetworkCounters` struct with shared atomics tracking bytes
  in/out, messages received/relayed/stored, failed validations, rate-limited requests.
  Wired into NetworkService gossip handlers for real-time tracking.
- **Alert engine** — background task evaluating configurable thresholds every 30 seconds.
  Conditions: IPFS unreachable, low peers, high disk/memory, SC sync lag. Dispatchers:
  Telegram, Discord, generic webhook. Severity levels: critical, warning, info.
  Cooldown support to prevent spam. (spec 10-dashboard.md §9)
- **`[alerts.ogmara_channel]` config** — configuration for posting alerts to an Ogmara
  private channel using the operator's wallet identity. (dispatcher implementation in
  next version)
- **`[metrics]` config section** — configurable sampling intervals for system (10s),
  IPFS (30s), storage (60s), and ring buffer capacity (1440 slots = 24h).
- **`admin_wallets` and `session_ttl_hours`** in `[api.admin]` config — preparation
  for wallet-signature dashboard authentication (auth endpoints in next version).
- **`Storage::estimate_db_size()`** — estimates live data size across all column families.
- **`Storage::cf_stats()`** — returns per-CF key count and size estimates.
- **`IpfsClient::repo_stat()`** — queries IPFS repo size and object count.

### Changed
- **Dashboard WebSocket payload** upgraded to v2 format with structured sections:
  `node`, `system`, `network`, `storage`, `ipfs`, `chain`, `anchoring`.
- **Alert severity levels** standardized to `critical`/`warning`/`info` (was
  `error`/`warning`/`info`). Node restart alert renamed to `node_started` (info
  severity, fires on every startup for uptime tracking).

## [0.22.0] - 2026-04-06

### Added
- **Connected peers in `/api/v1/network/nodes`** — peers that are connected via
  libp2p but haven't sent a `NodeAnnouncement` yet now appear in the nodes list.
  Uses the Identify protocol to extract the peer's Ed25519 public key and compute
  their Ogmara node_id. Entries are added on connection and removed on disconnect.
  This ensures the dashboard shows all reachable nodes, not just those that have
  completed the 5-minute announcement cycle.

## [0.21.0] - 2026-04-06

### Added
- **GossipSub publishing from API layer** — messages submitted via `POST /api/v1/messages`
  are now published to the appropriate GossipSub topic after validation and storage.
  Previously, accepted messages were stored locally but never forwarded to peers — the
  API layer had no connection to the network layer. Added an `mpsc` channel from the
  API to the network event loop for gossip publishing. Topic routing covers chat
  messages (channel topics), news posts (global), profile updates, DMs (recipient
  topic), and node announcements (network topic).

## [0.20.1] - 2026-04-06

### Fixed
- **Sync rejects historical messages** — the message router applied the ±5 minute
  timestamp drift check to synced historical messages, rejecting 79 of 81 messages
  in testing. Added `process_synced_message()` which skips timestamp and rate-limit
  validation while still enforcing signature, identity, and payload checks.
- **GossipSub mesh can't form with <5 peers** — the default `mesh_n_low=5` meant
  GossipSub couldn't form a mesh with fewer than 5 nodes, so `publish()` never
  reached the other node. NodeAnnouncements were published locally but never
  delivered. Tuned mesh parameters: `mesh_n=3, mesh_n_low=1, mesh_outbound_min=1`
  so the mesh forms with as few as 1 peer.

## [0.20.0] - 2026-04-06

### Added
- **Periodic NodeAnnouncement publishing** — the node now announces itself to
  the `/ogmara/v1/network` GossipSub topic every 5 minutes, and immediately on
  first peer connection. The announcement includes node_id, served channels,
  user count, capabilities, and public API URL. This is how nodes discover each
  other and appear in the `/api/v1/network/nodes` endpoint and the website's
  network dashboard. Previously, NodeAnnouncement was defined in the protocol
  but never published — nodes were invisible to each other.

## [0.19.0] - 2026-04-06

### Added
- **Sync protocol: initial message sync on peer connection** — when a peer is
  identified as an Ogmara node, the node sends `SyncRequest` for every subscribed
  channel, requesting messages after the latest Lamport timestamp already stored
  locally. This is how new nodes catch up on historical messages.
- `Storage::latest_channel_timestamp()` — finds the most recent Lamport timestamp
  for a channel by seeking to the end of the CHANNEL_MSGS index.
- `Storage::iter_cf_from()` — iterates a column family from a seek position,
  bounded by a prefix. Used for incremental sync (after_timestamp filtering).

### Fixed
- **Sync response was never sent** — `handle_sync_request()` built the response
  from local storage but dropped the `ResponseChannel` without sending it. The
  production node was preparing messages but never delivering them to the requester.
  Now `send_response()` is called on the swarm's request-response behaviour.
- **`after_timestamp` filter was ignored** — `fetch_channel_messages()` ignored
  the `after_timestamp` field, always returning messages from the start. Now seeks
  to the correct position in the CHANNEL_MSGS index.

## [0.18.0] - 2026-04-06

### Added
- **Auto-subscribe to channel GossipSub topics** — the node now subscribes to
  `/ogmara/v1/channel/{id}` for every channel it knows about. On startup, all
  existing channels from storage are subscribed. When the chain scanner discovers
  new channels, it notifies the network layer via an internal channel to subscribe
  immediately. Previously, only pinned channels and the three default topics
  (network, profile, news/global) were subscribed — meaning the node never
  received or relayed channel messages over GossipSub.
- `tokio::mpsc` bridge from chain scanner to network service for real-time
  channel topic subscription on discovery.

## [0.17.1] - 2026-04-06

### Fixed
- **Chain scanner rate limiting (HTTP 429)** — new nodes syncing from block 0 were
  hammering the Klever API with back-to-back requests, causing persistent 429 errors.
  Added exponential backoff (5s base, doubles each time, 120s cap) on rate-limit
  responses, inter-batch delays (500ms catch-up, 200ms near tip), and larger batch
  sizes during catch-up (2000 blocks vs 500 near tip).
- **Transaction API filtering** — queries now filter by `type=63` (SC invoke) and
  `toAddress=<contract>` server-side, dramatically reducing response size and API load.
  Previously fetched ALL transactions and filtered locally.
- **Missing transaction pagination** — the scanner now pages through all results
  instead of only processing the first 100 transactions per block range. Capped at
  50 pages with a warning if hit.
- Unparseable transactions now logged at debug level instead of silently skipped.

## [0.17.0] - 2026-04-06

### Added
- **Connection event diagnostics** — `OutgoingConnectionError`, `IncomingConnectionError`,
  and `Dialing` swarm events are now handled and logged. Previously these were silently
  swallowed by a catch-all handler, making handshake failures invisible.
- **Kademlia bootstrap integration** — bootstrap node peer IDs are extracted from
  multiaddrs and added to the Kademlia routing table before dialing. Kademlia
  `bootstrap()` is triggered on first peer connection and retried every 30 seconds.
  Previously Kademlia always reported "No known peers" because bootstrap nodes were
  never registered in the DHT.
- **Connection limits** — `max_peers` config is now enforced via libp2p's
  `connection_limits::Behaviour`. Inbound connections are capped at half of
  `max_peers` (default 25) to prevent resource exhaustion from a single source.

### Changed
- `ConnectionEstablished` and `ConnectionClosed` events upgraded from `debug!` to
  `info!` level with additional fields: direction (inbound/outbound), remote address,
  total peer count, and close cause
- `Identify::Received` upgraded from `debug!` to `info!` level with listen address count
- Kademlia `RoutingUpdated` events logged at `info!` level (was `debug!`)
- Identify address injection capped at 16 addresses per peer to mitigate routing
  table poisoning

### Fixed
- **Health endpoint peer count always 0** — the network layer now shares an atomic
  peer counter with the API layer. `ConnectionEstablished` and `ConnectionClosed`
  update the shared counter, so `/api/v1/health` and `/api/v1/network/stats` report
  the actual connected peer count.

### Security
- Added `memory-connection-limits` feature to libp2p to enforce `max_peers` config
- Capped Identify listen address injection (max 16 per peer) to prevent DHT poisoning

## [0.16.0] - 2026-04-06

### Added
- **State anchoring to Klever blockchain** — the node can now periodically compute
  a Merkle root of L2 state (users, channels, delegations) and submit it on-chain
  by invoking the `anchorState` endpoint on the Ogmara KApp smart contract. This
  creates verifiable trust anchors proving L2 state at each checkpoint.
- `StateAnchorer` background task (`chain/anchoring.rs`) with configurable interval,
  exponential backoff on failure, and graceful shutdown handling
- `[anchoring]` config section with `enabled`, `interval_seconds`, and optional
  `wallet_key` (supports `OGMARA_ANCHOR_WALLET_KEY` env var for secret management)
- `compute_current_state_root()` on `Storage` — iterates USERS, CHANNELS, and
  DELEGATIONS column families to build the Merkle tree and produce the state root
- `POST /admin/state/anchor` — trigger an immediate state anchor on-demand
- `GET /admin/state/latest` — returns the current Merkle root, message/channel/user
  counts, and last anchor timestamp
- Full Klever TX construction flow: build → decode hash → Ed25519 sign → broadcast
- Unit tests for hex encoding and SC call data construction

### Security
- Anchor wallet key is redacted in Debug output and skipped during serialization
- Supports loading wallet key from environment variable instead of config file
- Intermediate key material is zeroized after use
- HTTP status codes checked before parsing Klever API responses

## [0.15.0] - 2026-04-05

### Added
- **Device address prefix (`ogd1...`)** — device keys now use a distinct bech32
  prefix `ogd` instead of `klv`, making them visually distinguishable from wallet
  addresses. Prevents confusion between ephemeral device keys and wallet identities.
- `device_pubkey_to_address()` function in crypto module for encoding device
  public keys with the `ogd` HRP
- `is_device_address()` helper to check if an address uses the device prefix
- One-time startup migration (`migrate_device_hrp`) re-derives all existing
  device addresses in `DEVICE_WALLET_MAP` and `WALLET_DEVICES` from `klv1` to
  `ogd1` format

### Changed
- `address_to_pubkey_bytes()` and `address_to_verifying_key()` now accept both
  `klv1...` (wallet) and `ogd1...` (device) addresses
- Auth middleware accepts `ogd1...` device addresses in `X-Ogmara-Address` header
- `/api/v1/devices/register` now returns `ogd1...` device addresses
- Chain scanner writes `ogd1...` device addresses for on-chain delegations

## [0.14.0] - 2026-04-05

### Changed
- **Tiered identity access** — unverified wallets (no on-chain registration) can
  now use basic features: chat messages, news posts, comments, reactions, DMs,
  channel join/leave, follows, profile updates, and reports. Advanced features
  (edits, deletes, channel creation/management, moderation, private channels)
  still require on-chain registration via the Klever smart contract.
- `requires_verified_identity()` method on `MessageType` determines which
  messages need on-chain verification vs. just a valid signature
- Router Step 4d now checks `registered_at > 0` in the USERS record to
  distinguish on-chain registered users from profile-only records
- `ProfileUpdate`-created USERS records now set `registered_at: 0` (previously
  used the envelope timestamp), clearly distinguishing them from on-chain
  registrations set by the chain scanner

## [0.13.3] - 2026-04-05

### Added
- **Unread divider support** — `GET /channels/{id}/messages` now includes
  `last_read_ts` in the response when the caller is authenticated, enabling
  clients to render a "New messages" divider at the first unread message

## [0.13.2] - 2026-04-05

### Added
- **Incremental message fetching** — `after` query parameter on
  `GET /channels/{id}/messages` and `GET /dm/{address}/messages` endpoints.
  Clients can poll with `after=<latest_msg_id>` to fetch only new messages
  instead of re-fetching the entire history. Reduces server load and bandwidth.
- `prefix_iter_cf_after` storage method for efficient forward seeks past a
  cursor key in RocksDB column families

## [0.13.1] - 2026-04-04

### Fixed
- Stored notification JSON now uses SDK field names (`type`/`from` instead of
  `notification_type`/`author`, `channel_id` as string) — notifications now
  appear correctly on the web app's Notifications page

## [0.13.0] - 2026-04-04

### Added

- **Private channel anchor node model** — private channels are now hosted on a
  single anchor node (the creator's node) with no GossipSub metadata leakage.
  Members access private channels through their home node, which proxies
  authenticated requests to the anchor node via libp2p (spec §5.5.5)
- **New message type: `PrivateChannelKeyDistribution` (0x60)** — allows channel
  creators/admins to distribute encrypted group keys to members. The anchor node
  stores opaque key material but cannot decrypt it (spec §8.1.1)
- **New content request types**: `PrivateChannelMessages` (0x07) and
  `PrivateChannelKeys` (0x08) for authenticated cross-node private channel access
- **New API endpoints**: `GET/POST /api/v1/channels/{id}/keys` for fetching and
  distributing encrypted group key material (members-only, 404 for non-members)
- **New storage column families**: `private_channel_keys` (encrypted key material
  per epoch), `private_channel_anchors` (remote anchor node URLs)
- **Authenticated sync protocol** — `SyncRequest` now supports `requester`,
  `proof`, and `proof_timestamp` fields for Ed25519-signed membership proofs
  when accessing private channel data across nodes
- **`PrivateContentRequest` and `PrivateChannelSubscribe` types** — protocol
  structs for authenticated content fetching and live subscription streams

### Changed

- `ChannelInvitePayload` now includes `anchor_node: Option<String>` field
  (mandatory for private channels) — tells the invited user's node where to
  connect for the channel
- `NodeAnnouncementPayload.channels` now explicitly filters out private channels
  (type 0x02) when storing peer directory entries — defense-in-depth even if a
  misbehaving node includes them
- `ContentRequestType` extended with `PrivateChannelMessages` and
  `PrivateChannelKeys` variants

## [0.12.3] - 2026-04-04

### Fixed

- DM unread counts now exclude the requesting user's own messages (same fix as channels in v0.11.4)

## [0.12.2] - 2026-04-04

### Changed

- Private channel join now allowed via invite links by default — knowing the channel ID (via shared link) is treated as proof of invitation. Owners can disable this with `invite_links_disabled: true` in channel metadata

## [0.12.1] - 2026-04-04

### Fixed

- `GET /api/v1/channels/:id` now returns limited channel info (name, slug, description, type, member count) for private channels when the caller is not a member, instead of 404 — enables invite/join page to display channel details

## [0.12.0] - 2026-04-04

### Added
- **Notification engine wired into node startup** — `NotificationEngine` is now
  created during `Node::run()` and connected to both the GossipSub message pipeline
  and the REST API message submission endpoint
- Mention detection for `ChatMessage` and `NewsComment` — parses the `mentions`
  field and delivers notifications to locally connected users
- Push gateway integration — when `[push_gateway]` is configured, notifications
  are forwarded via HTTP POST to the push gateway with correct `PushTrigger` payload
- WebSocket user tracking — authenticated WS clients are registered/unregistered
  with the notification engine for real-time mention matching
- `RouteResult::Accepted` now carries `raw_bytes` for downstream processing
  without re-deserialization
- `NotificationEngine` uses `Arc<RwLock<HashSet>>` for thread-safe local user tracking
- `AppState::with_broadcast()` constructor for sharing the broadcast channel
  between the notification engine and WebSocket layer

## [0.11.6] - 2026-04-04

### Fixed

- User profile endpoint now returns `follower_count` and `following_count` from cached counts

## [0.11.5] - 2026-04-04

### Fixed

- Edited messages now return the updated content — `enrich_message_json` fetches the latest edit envelope and replaces the original payload with `EditPayload.content`

## [0.11.4] - 2026-04-04

### Added

- `GET /api/v1/settings` endpoint — returns encrypted settings with `encrypted_settings`, `nonce`, and `key_epoch` fields

### Fixed

- Settings sync now stores full payload (nonce + key_epoch) instead of just ciphertext, so clients can decrypt
- Unread counts no longer include the requesting user's own messages

## [0.11.3] - 2026-04-04

### Fixed

- Chat message reactions now included in API responses — `enrich_message_json` adds `reactions` field with emoji counts from `CHAT_REACTION_COUNTS` storage

## [0.11.2] - 2026-04-04

### Added

- **Self-entry in `/api/v1/network/nodes`**: Node now includes itself as the first entry in the node list with real data (node_id, channels, user_count, anchor_status) instead of relying solely on peer announcements
- **`NodeAnnouncement` persistence**: `NodeAnnouncement` (0xE0) messages are now stored in the `PEER_DIRECTORY` column family, populating the network node list from gossip
- **`public_url` config option**: New `[api]` config field to advertise the node's public API endpoint in the network node list

### Security

- **NodeAnnouncement identity verification**: Claimed `node_id` in announcements is verified against the envelope author's public key (`Base58(SHA-256(pubkey)[:20])`) to prevent spoofing
- **Announcement payload validation**: `api_endpoint` validated as HTTP/HTTPS URL (max 256 bytes), `channels` list capped at 10,000 entries
- **Peer directory size cap**: Maximum 10,000 entries; new nodes rejected when at capacity (existing nodes can still update)
- **TTL filtering**: Stale peer entries (past `last_seen + ttl_seconds`) excluded from API response

## [0.11.1] - 2026-04-02

### Fixed

- **ChannelUpdate not applied**: ChannelUpdate envelopes were authorized and validated but never written to storage — channel edits (name, description, logo, banner, website, tags) are now merged into existing channel metadata
- **Chain scanner overwrites L2 metadata**: On-chain `channelCreated` events were overwriting the full channel record with `display_name: None` and `description: None`, erasing the L2-provided values. The scanner now preserves existing `display_name`, `description`, and `member_count` when re-processing a known channel

## [0.11.0] - 2026-04-02

### Added
- **9 new column families** — `deletion_markers`, `edit_history`, `chat_reactions`,
  `chat_reaction_counts`, `reports`, `counter_votes`, `channel_mutes`,
  `settings_sync`, `notifications` with full key encoders and storage helpers.
- **Moderation routing** — `Report` (0x40), `CounterVote` (0x41), and `ChannelMute`
  (0x42) messages now stored and indexed. Reports and counter-votes tracked per
  target. Mutes stored with expiration support.
- **Account/Device routing** — `SettingsSync` (0x33) stores encrypted settings
  per user. `DeviceRevocation` (0x32) revokes device keys via identity resolver.
  `DeletionRequest` (0x50) soft-deletes single messages or all user news posts.
- **5 new API endpoints:**
  - `GET /api/v1/users/{address}/posts` — user's news posts with enrichment
  - `GET /api/v1/notifications` — persisted mention notifications (30-day retention)
  - `GET /api/v1/moderation/reports?target=<hex>` — transparency log with score
  - `GET /api/v1/moderation/user/{address}` — reputation profile with trust score
  - `GET /api/v1/account/export` — downloadable text file with all user data
- **Notification persistence** — NotificationEngine now stores notifications in
  the NOTIFICATIONS CF for API retrieval, not just WebSocket broadcast.
- **`create_channel` handler** — `POST /api/v1/channels` now returns
  `{ "ok": true, "msg_id": "...", "channel_id": N }` instead of generic post_message.
- **`enrich_message_json` helper** — centralized deletion/edit status enrichment
  applied to all message-returning endpoints.
- **Mute enforcement in API** — `get_channel_messages` adds `"muted": true` flag
  on messages from muted authors (content still delivered, clients hide by default).

### Changed
- All message-returning endpoints now check `DELETION_MARKERS` and `EDIT_HISTORY`,
  adding `"deleted": true` / `"edited": true` fields and blanking deleted payloads.
- Payload validators wired for CounterVote, ChannelMute, SettingsSync,
  DeviceRevocation, and DeletionRequest message types.

### Removed
- Stale TODO comment about ChannelDelete in router.rs (already implemented via API).

## [0.10.0] - 2026-04-02

### Added
- **Edit/Delete message routing (Phase 2)** — full routing pipeline for 8
  message types: ChatEdit, ChatDelete, ChatReaction, DirectMessageEdit,
  DirectMessageDelete, DirectMessageReaction, NewsEdit, NewsDelete.
- **`authorize_edit_delete` method** — verifies original message authorship,
  enforces 30-minute edit window, and requires registered user for NewsEdit.
- **`extract_channel_id` for ChatEdit/ChatDelete** — enables channel-scoped
  ban enforcement for edit and delete operations.
- **`update_indexes` arms** — stores edit history (EDIT_HISTORY CF), deletion
  markers (DELETION_MARKERS CF), and chat reactions (CHAT_REACTIONS CF). DM
  reactions are encrypted and intentionally not indexed.
- **Payload validators** — `validate_chat_edit`, `validate_chat_delete`,
  `validate_dm_edit`, `validate_dm_delete`, `validate_news_edit`,
  `validate_news_delete` with type-specific length limits.
- **Type-specific validation dispatch** — Edit and Delete payloads now route
  to the correct validator based on `msg_type` (chat vs DM vs news limits).

## [0.9.7] - 2026-04-02

### Fixed
- **Device-signed registration rejected unnecessarily** — removed USERS CF
  existence check that blocked device-signed claims for wallets not yet
  registered on-chain. The device auth check (caller = device) is sufficient
  security. Added server-side logging for registration success/failure to
  aid debugging.

## [0.9.6] - 2026-04-02

### Added
- **Device-signed registration fallback** — `POST /api/v1/devices/register`
  now accepts device-signed claims (in addition to wallet-signed). When the
  wallet signature fails verification, the server checks if the claim was
  signed by the device key itself. Requires: caller must be the device (auth
  headers), and wallet must be a registered on-chain user (USERS CF).
  Enables K5 mobile browser device registration where `signMessage` is
  unavailable.

## [0.9.5] - 2026-04-02

### Fixed
- **Startup migration: backfill DEVICE_WALLET_MAP from DELEGATIONS** — v0.9.4
  fixed the scanner for new delegations, but existing delegations (already
  processed before the fix) were never backfilled. This one-time startup
  migration reads all active entries from `DELEGATIONS`, converts hex pubkeys
  to klv1 addresses, and creates the missing `DEVICE_WALLET_MAP` + `WALLET_DEVICES`
  entries. Fixes K5 wallet users unable to see private channels, DMs, or
  bookmarks on the web app opened in K5 browser.

## [0.9.4] - 2026-04-02

### Fixed
- **K5 delegation identity resolution broken** — chain scanner stored device
  delegations in `DELEGATIONS` CF but never wrote to `DEVICE_WALLET_MAP`.
  The auth middleware uses `DEVICE_WALLET_MAP` for device → wallet resolution,
  so K5-delegated devices were never resolved to their wallet address. All
  operations (channel access, DMs, unread counts) used the device address
  instead of the wallet address, causing cross-device identity mismatch.
  Scanner now writes both `DEVICE_WALLET_MAP` and `WALLET_DEVICES` entries
  when processing `DeviceDelegated` events.

## [0.9.3] - 2026-04-02

### Security
- **Private channel members/pins leak** — `GET /channels/:id/members` and
  `GET /channels/:id/pins` were fully public endpoints with no access control.
  Anyone could enumerate members and read pinned content of private channels.
  Now gated behind optional auth with `require_channel_access()` check.
- **Unread counts leaked private channels** — `GET /channels/unread` returned
  counts for all channels, revealing private channel IDs and activity to any
  authenticated user. Now filters out private channels the user isn't a member of.

### Changed
- Extracted `is_private_channel()` and `require_channel_access()` helpers to
  centralize the dual-format channel_type check across all endpoints.
- Moved `/channels/:id/members` and `/channels/:id/pins` from public routes
  to optional-auth routes.

## [0.9.2] - 2026-04-02

### Security
- **Router invite check bypassed for L2-created private channels** — the
  `ChannelJoin` authorization only checked `channel_type == 2` (integer), but
  L2-created channels stored it as `"Private"` (string). Users could join
  private channels without an invite. Now checks both forms.

### Fixed
- **channel_type serialization normalized** — router now stores `channel_type`
  as `u8` integer (matching the chain scanner) instead of serde enum string.
- **Startup migration** — one-time migration normalizes existing string
  `channel_type` values (`"Public"`, `"ReadPublic"`, `"Private"`) to integers
  (0, 1, 2) in the `CHANNELS` column family. Runs automatically on first boot.

## [0.9.1] - 2026-04-02

### Fixed
- **Private channel filter bypassed** — `channel_type` is stored as `"Private"`
  (string) by the message router but as `2` (integer) by the chain scanner.
  The privacy check only matched the integer form, so router-created private
  channels passed through the filter. Now checks both representations.

## [0.9.0] - 2026-04-02

### Security
- **Private channels exposed to everyone** — `list_channels`, `get_channel`, and
  `get_channel_messages` returned private channels (type 2) to all users including
  unauthenticated visitors. Private channels are now filtered from listings and
  return 404 for non-members on detail/messages endpoints.

### Added
- **Optional auth middleware** — `optional_auth_middleware` parses auth headers
  when present but passes through without error when missing. Used on public
  endpoints that need to optionally know the caller's identity.
- `check_channel_access()` helper — reusable private channel membership check
  used across list, detail, and messages endpoints.

## [0.8.4] - 2026-04-02

### Fixed
- **Chain scanner missing creator member** — channels created via on-chain events
  did not add the creator to `CHANNEL_MEMBERS` with role `"creator"`. This caused
  the web admin dashboard to be hidden for channel owners. Scanner now adds the
  creator as first member on new channel creation (consistent with message router).

## [0.8.3] - 2026-04-02

### Fixed
- **Channel deletion resurrection bug** — chain scanner unconditionally re-created
  deleted channels from on-chain `ChannelCreated` events. Added `DELETED_CHANNELS`
  tombstone column family; scanner now skips tombstoned channel IDs.
- **Incomplete channel cleanup** — `delete_channel` handler now also removes
  moderator records from `CHANNEL_MODERATORS` and decrements `TOTAL_CHANNELS`.
- **Non-atomic deletion** — tombstone write + channel metadata delete now use
  `WriteBatch` for crash-safe atomicity.
- **Silent error swallowing** — cleanup operations now log warnings on failure
  instead of discarding errors with `let _ =`.

### Added
- `DELETED_CHANNELS` column family — tombstone set (channel_id → deletion timestamp)
  prevents chain scanner from resurrecting intentionally deleted channels.
- `Storage::decrement_stat()` — saturating decrement for u64 stat counters.

## [0.7.0] - 2026-04-01

### Added
- **Direct Messaging endpoints** — full DM retrieval and read-state tracking:
  - `GET /api/v1/dm/conversations` — list DM conversations with peer address,
    last message preview, timestamp, and unread count. Paginated, deduplicated.
  - `GET /api/v1/dm/{address}/messages` — retrieve messages in a DM conversation.
    Computes conversation_id from auth user + path address.
  - `POST /api/v1/dm/{address}/read` — mark DM conversation as read (wall-clock cursor).
  - `GET /api/v1/dm/unread` — get unread DM counts per conversation, capped at 99.
- `DM_READ_STATE` column family — per-user per-conversation read cursors.
- `compute_conversation_id` — Keccak-256 of lexicographically sorted wallet addresses.
- `validate_direct_message` — validates recipient address, sender != recipient,
  content length, and conversation_id correctness.
- DM conversation index writes in `update_indexes` — both sender and recipient
  get entries in `DM_CONVERSATIONS` with the peer address stored as value.

### Fixed
- **DM_MESSAGES prefix extractor** — changed from 8 bytes to 32 bytes to match
  the conversation_id key prefix. Previous value caused incorrect bloom filter behavior.
- **DM_CONVERSATIONS prefix extractor** — changed from 8 bytes to 44 bytes to match
  klv1 bech32 address length.
- Address validation on DM GET endpoints — rejects non-klv1 or wrong-length addresses.

## [0.6.4] - 2026-04-01

### Added
- **Channel read state** — new `CHANNEL_READ_STATE` column family stores
  per-user per-channel read cursors (wall-clock timestamps).
- `POST /api/v1/channels/{channel_id}/read` — mark channel as read.
- `GET /api/v1/channels/unread` — get unread message counts per channel,
  comparing envelope timestamps against the read cursor. Capped at 99.

## [0.6.3] - 2026-04-01

### Fixed
- **Chain scanner no longer wipes profile data** — `UserRegistered` events
  now merge with existing user records, preserving `display_name`,
  `avatar_cid`, and `bio`. Previously, re-scanning a registration block
  would overwrite the entire record with empty profile fields.

## [0.6.2] - 2026-04-01

### Changed
- **API responses now return wallet addresses as author** — `envelope_to_json`
  resolves device keys to wallet addresses via the IdentityResolver. Clients
  always see the canonical wallet identity, never ephemeral device keys.
- `GET /api/v1/users/:address` now resolves device addresses to wallet
  addresses before profile lookup, so lookups by device key find the correct
  profile stored under the wallet address.
- `comment_count` added to `GET /api/v1/news` list response.
- Identity resolution errors are now logged instead of silently ignored.

## [0.6.1] - 2026-04-01

### Added
- **GET /api/v1/news/{msg_id}** — single news post endpoint returning the
  full post with engagement counts and a list of comments, enabling the
  web app's thread view.
- `comment_count` field in the `GET /api/v1/news` list response, allowing
  the feed to show how many comments each post has.

## [0.6.0] - 2026-04-01

### Added
- **Device-to-wallet identity mapping** (Phase 1: storage layer) — enables
  multi-device support where multiple device keys map to a single wallet address.
  New `DEVICE_WALLET_MAP` and `WALLET_DEVICES` column families in RocksDB.
  Storage methods: `register_device`, `revoke_device`, `resolve_wallet`, `list_devices`.
- **IdentityResolver** — in-memory DashMap cache backed by RocksDB for O(1)
  device→wallet resolution on hot paths. Bounded positive-only caching (50K max),
  cache warming at startup, structured logging for data corruption detection.
- 7 unit tests covering registration, resolution, revocation, multi-device,
  cache warming, and idempotent registration.
- **Auth middleware identity resolution** (Phase 2) — after signature verification,
  the middleware resolves device key → wallet address via IdentityResolver.
  `AuthUser` now has `address` (resolved wallet) and `signing_address` (device key).
  Fallback: if no mapping, device key IS the wallet (built-in wallet mode).
  Identity resolver warmed on node startup.
- **Device registration API** (Phase 3) — three new authenticated endpoints:
  `POST /api/v1/devices/register` (wallet-signed claim verification, max 10
  devices per wallet, caller binding), `DELETE /api/v1/devices/{device_address}`
  (wallet-owned revocation, sibling devices can manage each other),
  `GET /api/v1/devices` (list registered devices for authenticated wallet).
- **Message router identity resolution** (Phase 4) — after signature verification,
  `envelope.author` (device key) is resolved to wallet address via IdentityResolver.
  All storage/indexing, rate limiting, ban checks, and authorization use the
  resolved wallet identity. Signature verification still uses the device key.

### Fixed
- Ban expiration check now uses server wall-clock time instead of sender's
  claimed timestamp (prevents ban evasion via timestamp manipulation).
- Removed duplicate `NewsComment` match arm in `update_indexes`.
- Rate limiter counter uses `saturating_add` to prevent u32 overflow.

## [0.5.8] - 2026-04-01

### Changed
- Auth middleware now logs address, method, path, and timestamp on signature
  verification failure for debugging 401 errors

## [0.5.7] - 2026-04-01

### Changed
- **Body size limit** — increased from 1 MB to 10 MB to support media uploads
  (avatar images, attachments). The IPFS client's own size validation still
  enforces the configured max_upload_size_mb limit.

## [0.5.6] - 2026-04-01

### Fixed
- **ProfileUpdate now stored** — `update_indexes` was missing a handler for
  `MessageType::ProfileUpdate`, so profile envelopes were accepted but the
  user record was never updated. Now merges display_name, avatar_cid, and
  bio into the USERS column family. Creates a new user record if none exists
  (unregistered users can set profiles per spec).

## [0.5.5] - 2026-04-01

### Added
- **Media upload endpoint** — `POST /api/v1/media/upload` accepts multipart
  file uploads, validates MIME type and size, and stores on IPFS via Kubo.
  Returns `{ cid, size, mime_type }`. Requires authentication.
- **Media retrieval endpoint** — `GET /api/v1/media/:cid` fetches content
  from IPFS by CID. Public, with immutable cache headers. Detects content
  type from magic bytes (PNG, JPEG, GIF, WebP, PDF).
- IPFS client now stored in AppState and shared with API handlers.

## [0.5.4] - 2026-04-01

### Added
- **Contract address in stats endpoint** — `GET /api/v1/network/stats` now
  returns `contract_address` from the node's `klever.contract_address` config.
  Web/desktop clients use this for on-chain operations (tipping, registration)
  without needing a separate env var.

## [0.5.3] - 2026-04-01

### Added
- **Network field in stats endpoint** — `GET /api/v1/network/stats` now returns
  a `network` field ("testnet" or "mainnet"), derived from the configured Klever
  node URL. Allows clients to display which network the node is connected to.

## [0.5.2] - 2026-03-31

### Added
- **Auto channel membership** — users are automatically added as channel
  members when they send their first ChatMessage to a channel. Previously
  member_count was always 0 because no join mechanism existed.
- **ChannelCreate handler** — `update_indexes` now processes ChannelCreate
  envelopes: stores channel metadata, adds creator as first member,
  increments total_channels counter
- **ChannelJoin/Leave handlers** — adds/removes members from the
  CHANNEL_MEMBERS column family
- **NewsComment indexing** — comments are now indexed in NEWS_COMMENTS
  CF by (post_id, timestamp, msg_id) for future retrieval

### Security
- Channel member check uses `get_cf` before adding to prevent duplicate
  entries (idempotent on repeated messages)

## [0.5.1] - 2026-03-31

### Added

- **Split message counters** — `total_news_messages` and `total_channel_messages`
  fields in `/api/v1/network/stats` response, replacing the single combined
  `total_messages` count (which is still available for backwards compatibility)
- **Counter migration** — existing nodes automatically rebuild the new split
  counters from NEWS_FEED and CHANNEL_MSGS indexes on first startup after
  upgrade, with a `COUNTERS_V2` sentinel to prevent repeated rebuilds

## [0.5.0] - 2026-03-31

### Changed

- **Chain scanner: batch block scanning** — scans 500 blocks per API call
  instead of one-by-one, reducing API requests by 500x and avoiding Klever
  testnet rate limits
- **Chain scanner: use API for block height** — switched from
  `node_url/node/status` (aggressive rate limiting) to
  `api_url/v1.0/block/list?limit=1` for latest block height
- **Chain scanner: parse SC calls from transaction data** — Klever API
  receipts don't contain SC event identifiers. Rewrote scanner to match
  transactions by `contract[0].parameter.address` and decode function
  calls from the hex-encoded `data[0]` field (`functionName@arg1@arg2`)
- **Parser rewrite** — `parse_receipt()` replaced with `parse_sc_call()`
  that decodes SC function names and arguments directly from transaction
  data instead of receipt topics
- **Channel ID resolution** — `createChannel` events now resolved via
  `getChannelBySlug` SC view query since the channel ID isn't in the
  call data

### Fixed

- Missing semicolon after `public_routes` chain in API router setup
- RocksDB `cf_handle` return type updated to `Arc<BoundColumnFamily>`
  for compatibility with newer `rocksdb` crate versions
- All `WriteBatch` operations now pass `&cf_handle` references correctly
- `KleverTransaction` struct updated to match actual Klever API response
  format (contract array with parameter.address, data array with hex calls)

## [0.4.0] - 2026-03-31

### Added

- **Live Network Stats** — `GET /api/v1/network/stats` now returns real counts
  for `total_messages`, `total_users`, and `total_channels` instead of hardcoded
  zeros, making the website status bar reflect actual network state
- Stat counter keys in `NODE_STATE` column family (`stat_total_messages`,
  `stat_total_users`, `stat_total_channels`) with `get_stat()` and
  `increment_stat()` storage methods
- Automatic counter rebuild on startup — scans existing `MESSAGES`, `USERS`,
  and `CHANNELS` column families when counters are zero (handles upgrade from
  pre-stats versions)
- `NEWS_COMMENTS` column family — indexes comments by parent post
  `(post_id, timestamp, msg_id)` for efficient comment retrieval
- `NewsComment` messages now indexed in `update_indexes()` (previously fell
  through to the catchall and were invisible to queries)
- `encode_news_comment_key()` key encoding function
- `get_comment_count()` method on `Storage` for per-post comment counts

### Fixed

- Website status bar showing `0 Users`, `0 Messages`, `0 Channels` despite
  having stored content — stats endpoint was returning hardcoded zeros
- `NewsComment` messages stored but never indexed, making them unqueryable

## [0.3.0] - 2026-03-30

### Added

- **Node Anchor Verification** — nodes that anchor L2 state on-chain are now
  tracked with verification levels (`active`, `verified`, `none`)
- `ANCHOR_BY_NODE` column family — reverse index of anchors by submitting node
  for efficient per-node anchor history queries
- `compute_anchor_status()` — determines verification level based on anchor
  consistency over the last 7 days
- `get_self_anchor_status()` — reports this node's own anchoring activity
- `GET /api/v1/network/stats` now includes `anchor_status` object with
  `is_anchorer`, `last_anchor_height`, `last_anchor_age_seconds`,
  `total_anchors`, `anchoring_since`
- `GET /api/v1/network/nodes` — new endpoint listing all known peers with
  per-node `anchor_status` (verified, level, last_anchor_age_seconds,
  anchoring_since)
- Chain scanner now writes anchor-by-node reverse index when processing
  `stateAnchored` events

## [0.2.0] - 2026-03-30

### Security
- Authorization guard for all channel admin operations (add/remove mod, kick, ban, pin, invite)
  - Creator-only actions enforced (moderator management)
  - Per-permission checks for moderators (can_kick, can_ban, can_pin, etc.)
  - Cannot kick/ban the channel creator
- Ban enforcement in message pipeline — banned users rejected from channel-scoped messages
- Ban expiration enforcement — temporary bans auto-expire on read and in pipeline
- Per-action-type rate limiting (7 categories per spec Part 5) replacing flat counter
- Rate limiter memory cleanup (evicts expired entries)
- Atomic WriteBatch for follow/unfollow, reaction toggle, repost count updates
- Proper error propagation replacing `unwrap_or_default()` on serialization
- Ban list endpoint moved behind authentication (moderator/creator only)
- Ban reason now required per spec section 2.6
- Monotonic pin sequence to prevent pin_order collisions
- ContentRequest.limit capped to 500 per spec
- Feed endpoint fan-out capped to 200 followed users
- Bookmark removal uses O(1) reverse index instead of O(N) scan

### Added
- **News Engagement**
  - NewsReaction (0x24) and NewsRepost (0x25) message types
  - ReactionPayload reuse for news reactions (like, dislike, love, fire, funny)
  - NewsRepostPayload with optional quote comment (max 512 chars)
  - Storage: news_reactions, reaction_counts, reposts, repost_counts, bookmarks CFs
  - API: GET/POST news reactions, GET/POST reposts, GET/POST/DELETE bookmarks
  - Toggle-based reaction counting with cached counts
  - Repost idempotency (can't repost same post twice, can't repost own post)

- **Channel Administration**
  - 8 new message types: ChannelAddModerator (0x14), ChannelRemoveModerator (0x15),
    ChannelKick (0x16), ChannelBan (0x17), ChannelUnban (0x18), ChannelPinMessage (0x19),
    ChannelUnpinMessage (0x1A), ChannelInvite (0x1B)
  - ModeratorPermissions struct (can_mute, can_kick, can_ban, can_pin, can_edit_info, can_delete_msgs)
  - Storage: channel_moderators, channel_bans, channel_pins, channel_members, channel_invites CFs
  - API: Full CRUD for moderators, bans, pins, invites, member listing
  - Pin message FIFO (max 10 per channel, oldest removed when limit exceeded)
  - Ban records with duration, reason, banned_by tracking

- **Channel Update Extensions**
  - logo_cid, banner_cid, website_url, tags fields on ChannelUpdatePayload
  - Validation for website_url (max 256), tags (max 5, each max 64 chars)

- **Validation**
  - Full validation for all 10 new message types
  - Address format checks (klv1 prefix) on all target_user fields
  - Reason length limits (max 256) for kick/ban payloads

## [0.1.0] - 2026-03-29

### Added
- **Phase 1 — Foundation**
  - Core types: 27+ MessageType enum entries with full payload structs
  - Crypto module: Ed25519 signing in Klever message, TX, and Ogmara protocol formats
  - Keccak-256 hashing, bech32 address encoding, key generation
  - RocksDB storage with 17 column families and key encoding functions
  - Configuration loading from ogmara.toml with safe defaults
  - CLI with run, init, and identity subcommands
  - Node identity management with Lamport clock (atomic CAS)

- **Phase 2 — Networking**
  - libp2p composed behaviour: GossipSub, Kademlia DHT, mDNS, Identify, Request-Response
  - GossipSub topic management (channel, DM, news, profile, network topics)
  - Peer directory with TTL-based staleness tracking
  - Sync protocol: CBOR request-response for on-demand content fetching
  - Message router: 11-step pipeline with Ed25519 signature verification
  - Per-user rate limiting with sliding time windows
  - Type-specific payload validation for all message types

- **Phase 3 — Chain Integration**
  - Klever block scanner with configurable polling interval and cursor persistence
  - SC event parsing for all 8 Ogmara contract events
  - Local state building in RocksDB from on-chain events
  - IPFS client: upload with pinning, bounded retrieval, CID validation, health check
  - MIME type allowlist for uploads

- **Phase 4 — API**
  - REST API with Axum: health, stats, channels, messages, users, news
  - Authenticated endpoints with Klever wallet signature verification
  - WebSocket: authenticated (full read/write) and public (read-only)
  - Admin endpoints with localhost-only enforcement via ConnectInfo
  - 1 MB request body size limit, proper CORS configuration

- **Phase 5 — Advanced**
  - Merkle tree with SHA-256 and domain separation (leaf/internal node prefixes)
  - State manager for computing state roots from users/channels/delegations
  - Notification engine with mention detection and push gateway integration
  - Alerting system: Telegram, Discord, webhook channels with cooldown
  - Embedded admin dashboard (self-contained HTML/CSS/JS, dark/light theme)
  - Dashboard metrics WebSocket with 2-second push interval

- **Social Features (backport)**
  - Follow/Unfollow message types (0x34, 0x35) with validation
  - Three storage column families: follows, followers, follower_counts
  - Bidirectional follow indexes with cached counts
  - API endpoints: followers, following, follow, unfollow, personal feed

### Security
- All ingestion paths (gossip + sync) route through MessageRouter
- Ed25519 signature verification on every message
- CID format validation on all IPFS API calls
- Admin endpoints locked to localhost via IP check middleware
- WebSocket auth verifies Klever signature
- Safe integer parsing (try_from, no silent truncation)
- Mentions capped at 50 per message (anti-amplification)
- Merkle domain separation prevents second-preimage attacks
