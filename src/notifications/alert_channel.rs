//! Ogmara-channel alert dispatch (audit final pre-mainnet W34).
//!
//! Posts an alert as an ordinary signed `ChatMessage` into a channel the
//! configured wallet is already a member of — the node acts as a
//! self-signing identity, the same way `NetworkAnnouncement`
//! (`network/mod.rs`) and `build_and_gossip_dual_delegation`
//! (`api/routes.rs`) already self-sign and inject other envelope types
//! directly through the router, bypassing the HTTP layer entirely.
//!
//! The operator must have already created the target channel and joined
//! this wallet as a member out-of-band (a client-app step) — there is no
//! node-side automation for that part, only for posting once membership
//! already exists.

use anyhow::Context;
use ed25519_dalek::SigningKey;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::mpsc;
use tracing::warn;

use crate::config::OgmaraChannelAlertConfig;
use crate::messages::envelope::{Envelope, PROTOCOL_VERSION};
use crate::messages::router::{MessageRouter, RouteResult};
use crate::messages::types::{ChatMessagePayload, ContentRating, MessageType};
use crate::network::GossipPublish;
use crate::storage::rocks::Storage;
use crate::storage::schema;

/// Bundle of everything needed to post a self-signed alert message into an
/// Ogmara channel. Constructed once at startup — `None` (in `AlertEngine`)
/// when `[alerts.ogmara_channel] enabled = false`, the key fails to load,
/// or the loaded key's derived address doesn't match `wallet_address`.
pub struct AlertChannelDispatcher {
    /// A DEDICATED `MessageRouter` instance, not the shared `AppState` one
    /// — mirrors the existing precedent that `NetworkService` already
    /// constructs its own independent router for gossip processing
    /// (`network/mod.rs`). `AlertEngine` has no `AppState` handle, and
    /// giving it one would be a much larger, unrelated change than this
    /// finding calls for.
    router: MessageRouter,
    /// Separate `Storage` handle (cheap to clone) for the pre-send
    /// encrypted-channel check — kept alongside `router` rather than
    /// reaching into it, since `MessageRouter` doesn't expose its
    /// internal storage.
    storage: Storage,
    gossip_tx: mpsc::UnboundedSender<GossipPublish>,
    klever_network: String,
    signing_key: SigningKey,
    wallet_address: String,
    channel_id: u64,
}

impl AlertChannelDispatcher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage: Storage,
        identity: crate::storage::identity::IdentityResolver,
        gossip_tx: mpsc::UnboundedSender<GossipPublish>,
        klever_network: String,
        signing_key: SigningKey,
        wallet_address: String,
        channel_id: u64,
        counters: std::sync::Arc<crate::metrics::counters::NetworkCounters>,
    ) -> Self {
        let router = MessageRouter::new(
            storage.clone(),
            identity,
            None, // no PoW — a self-originated, already-privileged post
            klever_network.clone(),
            usize::MAX, // dm_recipient_cap — not applicable, this router never sends DMs
            counters,
        );
        Self {
            router,
            storage,
            gossip_tx,
            klever_network,
            signing_key,
            wallet_address,
            channel_id,
        }
    }
}

/// Load the alert-posting wallet's Ed25519 signing key.
///
/// Precedence: `OGMARA_ALERT_SIGNING_KEY` env (hex) else
/// `signing_key_path` file contents (hex, trimmed). Returns `Ok(None)`
/// only for the legitimately-disabled case (no env, empty path) — mirrors
/// the anchor-wallet-key loading pattern in `node.rs` (env > config, both
/// wrapped in `SecretString` so the hex source zeroizes on drop).
///
/// A NON-empty `signing_key_path` that fails to read, or invalid hex/length
/// from either source, is a real misconfiguration and returns `Err` —
/// deliberately NOT collapsed into "disabled", so a typo'd path fails loud
/// at startup instead of silently never posting.
pub fn load_alert_signing_key(
    cfg: &OgmaraChannelAlertConfig,
) -> anyhow::Result<Option<SigningKey>> {
    let env_override = std::env::var("OGMARA_ALERT_SIGNING_KEY")
        .ok()
        .filter(|s| !s.is_empty());

    let hex_secret: Option<SecretString> = if let Some(env_hex) = env_override {
        Some(SecretString::from(env_hex))
    } else if cfg.signing_key_path.is_empty() {
        None
    } else {
        // Security Audit NOTE-2 fix: wrap the raw file contents into
        // `SecretString` immediately, with no intermediate `.trim().to_string()`
        // copy — that copy was a second, plain `String` holding the same
        // secret hex that (unlike `SecretString`) does NOT zeroize on drop.
        // Trimming happens later, on the already-wrapped secret's exposed
        // `&str` (see below), which never allocates a new un-wrapped copy.
        let contents = std::fs::read_to_string(&cfg.signing_key_path).with_context(|| {
            format!(
                "reading [alerts.ogmara_channel] signing_key_path '{}'",
                cfg.signing_key_path
            )
        })?;
        Some(SecretString::from(contents))
    };

    let Some(secret) = hex_secret else {
        return Ok(None);
    };

    let hex_str = secret.expose_secret().trim();
    let mut bytes =
        hex::decode(hex_str).context("decoding ogmara_channel alert signing key hex")?;
    // Security Audit NOTE-2 fix: check the length BEFORE building
    // `key_bytes`, zeroizing `bytes` on EITHER exit path. The previous
    // `try_into().map_err(...)?` returned on a length mismatch before
    // reaching the `bytes.fill(0)` below, leaving decoded secret bytes
    // unzeroized in the `Vec` that its `Drop` impl then just frees as-is.
    if bytes.len() != 32 {
        let len = bytes.len();
        bytes.fill(0);
        return Err(anyhow::anyhow!(
            "ogmara_channel alert signing key must be 32 bytes, got {len}"
        ));
    }
    let mut key_bytes: [u8; 32] = bytes.as_slice().try_into().expect("length checked above");
    let key = SigningKey::from_bytes(&key_bytes);
    // Zeroize both the decoded Vec and the intermediate array — same
    // discipline as the anchor-wallet-key block in `node.rs`. `SigningKey`
    // itself is ZeroizeOnDrop (ed25519-dalek 2.x), and `secret` zeroizes
    // when it drops at the end of this function.
    bytes.fill(0);
    key_bytes.fill(0);
    Ok(Some(key))
}

/// Post `message` as a signed `ChatMessage` into the configured Ogmara
/// channel. Returns `false` (never panics) on any failure — a broken alert
/// dispatcher must never crash the node or block the other dispatch
/// channels (telegram/discord/webhook) that already ran this tick.
pub async fn dispatch_ogmara_channel_alert(
    dispatcher: &AlertChannelDispatcher,
    message: &str,
) -> bool {
    // Refuse upfront if the target channel is encrypted (audit final
    // pre-mainnet W34 constraint) — this dispatcher has no channel key and
    // can never produce `enc_content`, so attempting anyway would just
    // reach the router's own `check_channel_encryption_required` gate and
    // get an opaque `Rejected` instead of a clear, actionable log line.
    let channel_key = dispatcher.channel_id.to_be_bytes();
    let channel_data = match dispatcher.storage.get_cf(schema::cf::CHANNELS, &channel_key) {
        Ok(Some(d)) => d,
        Ok(None) => {
            warn!(
                channel_id = dispatcher.channel_id,
                "ogmara_channel alert target channel not found locally; skipping post \
                 (has the alert wallet actually joined it?)"
            );
            return false;
        }
        Err(e) => {
            warn!(error = %e, channel_id = dispatcher.channel_id, "failed to read ogmara_channel alert target channel");
            return false;
        }
    };
    // Security Audit follow-up: FAIL CLOSED, not open. The original version
    // of this check treated "JSON parse failure", "encryption_enabled
    // field absent", and "field present but not a bool" all as `false`
    // (not encrypted) — but the chain scanner's own first-write skeleton
    // record (chain/scanner.rs) has NO `encryption_enabled` field at all
    // (chain discovery routinely precedes the L2 `ChannelCreate` that would
    // add it), so a channel could legitimately sit in `CHANNELS` in exactly
    // that "field absent" state while private/encrypted — and the old logic
    // would have posted plaintext into it. Two independent signals now both
    // have to affirmatively clear before posting: `channel_type` (private =
    // 2, always encrypted since P4 — checked even without a parseable
    // `encryption_enabled`) AND `encryption_enabled` itself (any parse
    // failure, absence, or non-bool value ⇒ treated as "assume encrypted,
    // refuse" — not "assume plain, post").
    let meta = match serde_json::from_slice::<serde_json::Value>(&channel_data) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, channel_id = dispatcher.channel_id, "ogmara_channel alert target channel record did not parse — refusing to post (fail closed)");
            return false;
        }
    };
    let is_private_type = meta.get("channel_type").and_then(|v| v.as_u64()) == Some(2);
    let encryption_enabled = meta.get("encryption_enabled").and_then(|v| v.as_bool());
    let refuse = is_private_type || encryption_enabled != Some(false);
    if refuse {
        warn!(
            channel_id = dispatcher.channel_id,
            channel_type_private = is_private_type,
            encryption_enabled = ?encryption_enabled,
            "ogmara_channel alert target channel is encrypted (or its encryption status \
             could not be positively confirmed as plain) — this dispatcher has no channel \
             key and can never post to it; configure a plain/public channel instead"
        );
        return false;
    }

    let payload = ChatMessagePayload {
        channel_id: dispatcher.channel_id,
        content: message.to_string(),
        content_rating: ContentRating::default(),
        reply_to: None,
        mentions: Vec::new(),
        attachments: Vec::new(),
        enc_content: None,
        enc_nonce: None,
        key_epoch: None,
    };
    let payload_bytes = match rmp_serde::to_vec_named(&payload) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to serialize ogmara_channel alert payload");
            return false;
        }
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let pubkey_bytes = dispatcher.signing_key.verifying_key().to_bytes();
    let msg_id = crate::crypto::compute_msg_id(
        &dispatcher.klever_network,
        &pubkey_bytes,
        &payload_bytes,
        now_ms,
    );
    let signature = crate::crypto::signing::sign_ogmara_message(
        &dispatcher.signing_key,
        &dispatcher.klever_network,
        PROTOCOL_VERSION,
        MessageType::ChatMessage as u8,
        &msg_id,
        now_ms,
        &payload_bytes,
    );

    let envelope = Envelope {
        version: PROTOCOL_VERSION,
        msg_type: MessageType::ChatMessage,
        msg_id,
        author: dispatcher.wallet_address.clone(),
        timestamp: now_ms,
        lamport_ts: 0,
        payload: payload_bytes,
        signature: signature.to_bytes().to_vec(),
        relay_path: Vec::new(),
    };
    let envelope_bytes = match envelope.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to serialize ogmara_channel alert envelope");
            return false;
        }
    };

    match dispatcher.router.process_message(&envelope_bytes) {
        RouteResult::Accepted { raw_bytes, .. } => {
            if let Some(topic) = crate::api::routes::gossip_topic_for_envelope(
                &envelope,
                &dispatcher.klever_network,
            ) {
                let _ = dispatcher.gossip_tx.send(GossipPublish {
                    topic,
                    data: raw_bytes,
                    respond_to: None,
                });
            }
            true
        }
        RouteResult::Duplicate => true,
        RouteResult::Rejected(reason) | RouteResult::Invalid(reason) => {
            warn!(reason = %reason, channel_id = dispatcher.channel_id, "router rejected ogmara_channel alert envelope");
            false
        }
        RouteResult::PowRequired { .. } => {
            warn!(channel_id = dispatcher.channel_id, "ogmara_channel alert unexpectedly required PoW");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    //! Audit final pre-mainnet W34. `load_alert_signing_key`'s
    //! disabled-vs-misconfigured distinction is the one piece of pure,
    //! easily-testable logic here (the dispatch path itself needs a full
    //! `MessageRouter`/`Storage`/gossip channel to exercise meaningfully —
    //! covered by the encrypted-channel-refusal test below instead, which
    //! only needs `Storage`).
    use super::*;
    use crate::config::OgmaraChannelAlertConfig;

    /// Serializes every test below that reads or writes
    /// `OGMARA_ALERT_SIGNING_KEY` (Code Audit NOTE #7). Env vars are
    /// process-global state; cargo's default multi-threaded test runner can
    /// otherwise interleave one test's `set_var`/`remove_var` with another's
    /// read and flip results depending on scheduling. Held for the whole
    /// body of each test (dropped at function return), not just around the
    /// `set_var`/`remove_var` calls, so a slower test can't have its env var
    /// yanked out from under it mid-assertion by a faster one.
    static ENV_VAR_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn disabled_when_no_env_and_empty_path() {
        let _guard = ENV_VAR_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: test-only env var read, serialized against other env-var
        // tests in this module by `ENV_VAR_TEST_LOCK` above.
        unsafe { std::env::remove_var("OGMARA_ALERT_SIGNING_KEY") };
        let cfg = OgmaraChannelAlertConfig::default();
        assert!(cfg.signing_key_path.is_empty());
        let result = load_alert_signing_key(&cfg).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn errors_loudly_on_unreadable_configured_path() {
        let _guard = ENV_VAR_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var("OGMARA_ALERT_SIGNING_KEY") };
        let mut cfg = OgmaraChannelAlertConfig::default();
        cfg.signing_key_path = "/nonexistent/path/that/should/not/exist/ogmara-alert.key".to_string();
        let result = load_alert_signing_key(&cfg);
        assert!(
            result.is_err(),
            "a NON-empty configured path that fails to read must be a loud error, \
             not silently treated as disabled"
        );
    }

    #[test]
    fn env_override_takes_precedence_over_path() {
        let _guard = ENV_VAR_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let hex_key = hex::encode(key.to_bytes());
        // SAFETY: test-only env var write, serialized by `ENV_VAR_TEST_LOCK`.
        unsafe { std::env::set_var("OGMARA_ALERT_SIGNING_KEY", &hex_key) };
        let mut cfg = OgmaraChannelAlertConfig::default();
        // A deliberately-broken path — must be ignored since env wins.
        cfg.signing_key_path = "/nonexistent/path".to_string();
        let result = load_alert_signing_key(&cfg).unwrap();
        unsafe { std::env::remove_var("OGMARA_ALERT_SIGNING_KEY") };
        assert_eq!(result.expect("env override must load successfully").to_bytes(), key.to_bytes());
    }

    /// Security Audit NOTE-2 regression: a wrong-length key must error
    /// loudly (not panic, not silently truncate/pad) — and exercises the
    /// zeroize-on-error-path fix above (`bytes.fill(0)` before the length-
    /// mismatch `bail!`, previously skipped by an early `?` return).
    #[test]
    fn wrong_length_key_errors_loudly() {
        let _guard = ENV_VAR_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::set_var("OGMARA_ALERT_SIGNING_KEY", "deadbeef") };
        let cfg = OgmaraChannelAlertConfig::default();
        let result = load_alert_signing_key(&cfg);
        unsafe { std::env::remove_var("OGMARA_ALERT_SIGNING_KEY") };
        assert!(result.is_err(), "a 4-byte hex key must be rejected, not silently accepted");
    }

    #[tokio::test]
    async fn refuses_to_post_to_an_encrypted_channel() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let channel_id = 999u64;
        storage
            .put_cf(
                schema::cf::CHANNELS,
                &channel_id.to_be_bytes(),
                &serde_json::to_vec(&serde_json::json!({
                    "member_count": 1,
                    "channel_type": 2,
                    "encryption_enabled": true,
                }))
                .unwrap(),
            )
            .unwrap();

        let identity = crate::storage::identity::IdentityResolver::new(storage.clone());
        let (gossip_tx, mut gossip_rx) = mpsc::unbounded_channel();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let wallet_address =
            crate::crypto::pubkey_to_address(&signing_key.verifying_key()).unwrap();
        let dispatcher = AlertChannelDispatcher::new(
            storage,
            identity,
            gossip_tx,
            "testnet".to_string(),
            signing_key,
            wallet_address,
            channel_id,
            std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()),
        );

        let posted = dispatch_ogmara_channel_alert(&dispatcher, "test alert").await;
        assert!(!posted, "must refuse to post to an encrypted channel");
        assert!(
            gossip_rx.try_recv().is_err(),
            "must never enqueue a gossip publish for a refused post"
        );
    }
}
