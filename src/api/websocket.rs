//! WebSocket handlers for real-time message streaming.
//!
//! Two WebSocket endpoints (spec 4.3):
//! - /api/v1/ws — authenticated, full read/write (subscribe, send messages, DMs)
//! - /api/v1/ws/public — no auth, read-only (subscribe to channels only)

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::Extension;
use axum::response::IntoResponse;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::crypto;
use crate::crypto::signing;

use super::state::AppState;

/// Auth message sent as the first WebSocket frame.
#[derive(Debug, Deserialize)]
struct WsAuthMessage {
    address: String,
    timestamp: u64,
    signature: String, // base64-encoded
    /// Client-chosen single-use nonce (hex). Required as of the
    /// 2026-06-07 host-binding fix — same scheme as the REST auth header.
    #[serde(default)]
    nonce: String,
    /// W5 dm-sync backfill authorization (optional, wallet-direct signature) —
    /// see `network::dm_sync` and `api::auth`'s module doc for the design.
    #[serde(default)]
    dm_sync_timestamp: Option<u64>,
    #[serde(default)]
    dm_sync_signature: Option<String>, // base64-encoded
    /// Private-channel-sync backfill authorization (l2-node 0.142.0,
    /// optional): wallet-direct, or device-signed by the frame's `address`
    /// when that is a delegated device — see `api::auth`'s module doc.
    #[serde(default)]
    pchansync_timestamp: Option<u64>,
    #[serde(default)]
    pchansync_signature: Option<String>, // base64-encoded
}

/// What a verified WS auth frame yields.
struct WsAuthResult {
    /// The address that signed the frame (wallet or device).
    address: String,
    /// Raw dm-sync claim (verified later against the resolved wallet).
    dm_sync_claim: Option<crate::network::dm_sync::WalletAuthClaim>,
    /// Raw pchansync claim (verified later against the resolved wallet).
    pchansync_claim: Option<super::auth::RawPchanSyncClaim>,
}

/// The fixed path the WS auth signature is bound to.
const WS_AUTH_PATH: &str = "/api/v1/ws";

/// Verify a WebSocket auth message (same scheme as REST auth headers).
///
/// Binds `network` + `node_id` (this node's own) and a single-use `nonce`
/// exactly like the REST verifier (audit 2026-06-07 host-binding), so a
/// captured WS-auth frame is neither fleet-portable nor same-node replayable.
async fn verify_ws_auth(text: &str, state: &AppState) -> Result<WsAuthResult, String> {
    let auth: WsAuthMessage =
        serde_json::from_str(text).map_err(|e| format!("invalid auth JSON: {}", e))?;

    super::auth::validate_nonce(&auth.nonce)?;
    super::auth::check_timestamp_fresh(auth.timestamp)?;

    // Decode signature
    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &auth.signature,
    )
    .map_err(|_| "invalid base64 signature")?;

    if sig_bytes.len() != 64 {
        return Err("signature must be 64 bytes".into());
    }

    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|_| "invalid signature bytes")?;

    let verifying_key = crypto::address_to_verifying_key(&auth.address)
        .map_err(|e| format!("invalid address: {}", e))?;

    signing::verify_auth_header(
        &verifying_key,
        &state.klever_network,
        &state.node_id,
        &auth.nonce,
        auth.timestamp,
        "GET",
        WS_AUTH_PATH,
        &signature,
    )
    .map_err(|_| "signature verification failed")?;

    // Burn the nonce (same-node replay protection).
    super::auth::claim_nonce(state, &auth.address, &auth.nonce).await?;

    // W5: raw (unverified against the RESOLVED wallet) claim, if attached —
    // the caller self-verifies once it knows the resolved wallet address.
    let wallet_claim_raw = auth.dm_sync_timestamp.zip(auth.dm_sync_signature.as_deref()).and_then(
        |(timestamp, sig_b64)| {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
                .ok()
                .map(|signature| crate::network::dm_sync::WalletAuthClaim { timestamp, signature })
        },
    );

    let pchansync_claim = super::auth::decode_pchansync_claim(
        auth.pchansync_timestamp,
        auth.pchansync_signature.as_deref(),
    );

    Ok(WsAuthResult {
        address: auth.address,
        dm_sync_claim: wallet_claim_raw,
        pchansync_claim,
    })
}

// --- WebSocket message types ---

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
enum WsClientMessage {
    Subscribe { channels: Vec<String> },
    Unsubscribe { channels: Vec<String> },
    SubscribeDm,
    Message { envelope: serde_json::Value },
    Dm { envelope: serde_json::Value },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
enum WsServerMessage {
    Error { code: u16, message: String },
}

// --- Authenticated WebSocket ---

/// WS /api/v1/ws — authenticated WebSocket endpoint.
pub async fn ws_authenticated(
    ws: WebSocketUpgrade,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_authenticated_ws(socket, state))
}

async fn handle_authenticated_ws(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    // First message must be auth with Klever wallet signature
    let auth_text = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        receiver.next(),
    )
    .await
    {
        Ok(Some(Ok(Message::Text(text)))) => text,
        _ => {
            let _ = sender
                .send(Message::Text(
                    serde_json::to_string(&WsServerMessage::Error {
                        code: 401,
                        message: "auth required as first message".into(),
                    })
                    .unwrap_or_default()
                    .into(),
                ))
                .await;
            return;
        }
    };

    // Parse and verify auth message
    let auth_result = verify_ws_auth(&auth_text, &state).await;
    let (auth_address, wallet_claim_raw, pchansync_raw) = match auth_result {
        Ok(r) => {
            debug!(address = %r.address, "WebSocket client authenticated");
            (r.address, r.dm_sync_claim, r.pchansync_claim)
        }
        Err(e) => {
            let _ = sender
                .send(Message::Text(
                    serde_json::to_string(&WsServerMessage::Error {
                        code: 401,
                        message: format!("auth failed: {}", e),
                    })
                    .unwrap_or_default()
                    .into(),
                ))
                .await;
            return;
        }
    };

    // Resolve device key → wallet address for notification matching.
    // Mentions in messages reference wallet addresses, so we must register
    // the wallet address (not the device/signing key) with the engine.
    let wallet_address = state.identity.resolve(&auth_address).unwrap_or_else(|_| auth_address.clone());

    // W5: self-verify the raw claim against the RESOLVED wallet before
    // handing it to the network task (a device-signing-address claim
    // wouldn't match — this claim is deliberately wallet-direct only).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let wallet_claim = wallet_claim_raw.filter(|c| {
        crate::network::dm_sync::verify_wallet_claim(c, &state.klever_network, &state.node_id, &wallet_address, now)
    });

    // Subscribe this node to the user's DM gossip topic so DMs sent to them from
    // OTHER nodes are received and indexed here (the network task owns the swarm).
    // Idempotent in the topic layer; safe to send on every connect.
    //
    // Gated on PoW-known (audit final pre-mainnet W11) — same rationale and
    // fail-open shape as the REST auth path (`api/auth.rs`).
    let dm_enrollment_allowed = state
        .pow
        .as_ref()
        .map(|pow| pow.is_wallet_known(&wallet_address))
        .unwrap_or(true);
    if dm_enrollment_allowed {
        let _ = state.dm_subscribe_tx.send(crate::network::DmSubscribeEvent {
            wallet: wallet_address.clone(),
            wallet_claim,
        });
    }

    // l2-node 0.142.0: private-channel-sync claim (wallet-direct or
    // device-signed by `auth_address`), same handling as the REST path.
    super::auth::process_pchansync_claim(&state, &wallet_address, &auth_address, pchansync_raw).await;

    // Register this user with the notification engine for mention detection
    if let Some(ref engine) = state.notification_engine {
        engine.add_local_user(&wallet_address).await;
    }

    // Subscribe to broadcast channel for forwarding messages
    let mut broadcast_rx = state.ws_broadcast.subscribe();

    // Process messages in both directions
    loop {
        tokio::select! {
            // Forward broadcast messages to client — but only those whose
            // audience includes this connection's authenticated wallet, so a
            // DM is delivered only to its participants, never to every client.
            Ok(out) = broadcast_rx.recv() => {
                if out.audience.allows(&wallet_address)
                    && sender
                        .send(Message::Text(out.json.clone().into()))
                        .await
                        .is_err()
                {
                    break;
                }
            }
            // Handle client messages
            client_msg = receiver.next() => {
                match client_msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Err(e) = handle_ws_client_message(&text, &state, &wallet_address, &mut sender).await {
                            warn!(error = %e, "WebSocket client message error");
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    // Unregister user from notification engine on disconnect
    if let Some(ref engine) = state.notification_engine {
        engine.remove_local_user(&wallet_address).await;
    }

    debug!(address = %auth_address, "WebSocket client disconnected");
}

/// Handle a parsed client WebSocket message.
async fn handle_ws_client_message(
    text: &str,
    state: &Arc<AppState>,
    wallet: &str,
    _sender: &mut SplitSink<WebSocket, Message>,
) -> anyhow::Result<()> {
    let msg: WsClientMessage = serde_json::from_str(text)?;

    match msg {
        WsClientMessage::Subscribe { channels } => {
            debug!(channels = ?channels, "WS subscribe");
            // Channel subscription management happens at the network layer
        }
        WsClientMessage::Unsubscribe { channels } => {
            debug!(channels = ?channels, "WS unsubscribe");
        }
        WsClientMessage::SubscribeDm => {
            debug!("WS subscribe DM");
        }
        WsClientMessage::Message { envelope } => {
            submit_ws_envelope(state, wallet, &envelope, false).await;
        }
        WsClientMessage::Dm { envelope } => {
            submit_ws_envelope(state, wallet, &envelope, true).await;
        }
    }

    Ok(())
}

/// Route one envelope a client submitted over the authenticated WebSocket
/// (`Message` or `Dm` frame — `dm` only changes the log line; the frame
/// variant does not constrain `msg_type`) and run the side effects of an
/// accepted one: local member evidence, gossip relay, notification engine
/// and bot-descriptor broadcast.
///
/// Side effects are skipped for a key wrap that was already present (not
/// stored) and — l2-node 0.151.0, audit W-A — for a message erased on
/// arrival by a pending GDPR deletion request: it is stored hidden, so it is
/// neither relayed nor fed to the notification engine.
async fn submit_ws_envelope(state: &Arc<AppState>, wallet: &str, envelope: &serde_json::Value, dm: bool) {
    let Ok(bytes) = rmp_serde::to_vec(envelope) else { return };
    let result = state.router.process_message(&bytes);
    if dm {
        debug!(result = ?result, "WS DM processed");
    } else {
        debug!(result = ?result, "WS message processed");
    }
    let crate::messages::router::RouteResult::Accepted {
        raw_bytes,
        bot_commands_changed,
        key_status,
        author,
        erased_on_arrival,
        ..
    } = result
    else {
        return;
    };
    // Private-channel lifecycle (l2-node 0.149.0): local member evidence
    // when the connection's wallet authored it.
    super::routes::note_local_channel_activity(state, &raw_bytes, &author, wallet);
    if erased_on_arrival {
        debug!("WS-submitted message erased on arrival by a pending deletion request; not relayed");
        return;
    }
    // An already-present key wrap was not stored: no relay.
    let relay = key_status != Some(crate::messages::router::KeyStatus::AlreadyPresent);
    // Gossip does not loop back to the publisher, so without this the node a
    // bot submits through is the only one that never tells its own clients.
    // Handled for both frame variants: a client can submit a ProfileUpdate
    // through `Dm` and the router will accept it.
    if let Some(bot_wallet) = bot_commands_changed {
        if let Some(ref engine) = state.notification_engine {
            let engine = engine.clone();
            tokio::spawn(async move {
                engine.broadcast_bot_commands_changed(&bot_wallet).await;
            });
        }
    }
    // Audit W26: WS-submitted content must federate like the REST path.
    if relay {
        super::routes::gossip_if_applicable(state, &raw_bytes).await;
    }
    // Mention detection (the `Message` frame only, as before).
    if !dm {
        if let Some(ref engine) = state.notification_engine {
            let engine = engine.clone();
            tokio::spawn(async move {
                if let Ok(env) = rmp_serde::from_slice::<crate::messages::envelope::Envelope>(&raw_bytes) {
                    engine.process(&env).await;
                }
            });
        }
    }
}

// --- Public WebSocket (read-only) ---

/// WS /api/v1/ws/public — public read-only WebSocket.
pub async fn ws_public(
    ws: WebSocketUpgrade,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_public_ws(socket, state))
}

async fn handle_public_ws(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut broadcast_rx = state.ws_broadcast.subscribe();

    loop {
        tokio::select! {
            // Public (unauthenticated) WS: forward only `Everyone`-audience
            // frames (public-channel messages) — never a participant-private DM.
            Ok(out) = broadcast_rx.recv() => {
                if out.audience.allows("")
                    && sender
                        .send(Message::Text(out.json.clone().into()))
                        .await
                        .is_err()
                {
                    break;
                }
            }
            client_msg = receiver.next() => {
                match client_msg {
                    Some(Ok(Message::Text(text))) => {
                        // Public WS only allows subscribe/unsubscribe
                        if let Ok(msg) = serde_json::from_str::<WsClientMessage>(&text) {
                            match msg {
                                WsClientMessage::Subscribe { channels } => {
                                    debug!(channels = ?channels, "Public WS subscribe");
                                }
                                WsClientMessage::Unsubscribe { channels } => {
                                    debug!(channels = ?channels, "Public WS unsubscribe");
                                }
                                _ => {
                                    let err = WsServerMessage::Error {
                                        code: 403,
                                        message: "public WebSocket is read-only".into(),
                                    };
                                    let _ = sender
                                        .send(Message::Text(
                                            serde_json::to_string(&err).unwrap_or_default().into(),
                                        ))
                                        .await;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    debug!("Public WebSocket client disconnected");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ws_auth_frame_carries_the_pchansync_claim() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = crate::storage::rocks::Storage::open(dir.path()).unwrap();
        let identity = crate::storage::identity::IdentityResolver::new(storage.clone());
        let router = crate::messages::router::MessageRouter::new(
            storage.clone(),
            identity.clone(),
            None,
            "testnet".into(),
            usize::MAX,
            Arc::new(crate::metrics::counters::NetworkCounters::new()),
            crate::config::RateLimitsConfig::default(),
        );
        let state = AppState::new(
            storage, router, "wsNode".into(), "testnet".into(), String::new(), String::new(), None, identity,
            None, None, None,
        );
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let addr = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let nonce = "00112233445566778899aabbccddeeff";
        let sig = signing::sign_auth_header(&sk, "testnet", "wsNode", nonce, ts, "GET", WS_AUTH_PATH);
        let b64 = |b: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b);
        let frame = serde_json::json!({
            "address": addr,
            "timestamp": ts,
            "signature": b64(&sig.to_bytes()),
            "nonce": nonce,
            "pchansync_timestamp": ts,
            "pchansync_signature": b64(&[7u8; 64]),
        });
        let r = verify_ws_auth(&frame.to_string(), &state).await.unwrap();
        assert_eq!(r.address, addr);
        let c = r.pchansync_claim.expect("claim parsed");
        assert_eq!((c.timestamp, c.signature.len()), (ts, 64));
        // Absent fields → no claim; an over-long signature field is ignored.
        assert!(crate::api::auth::decode_pchansync_claim(Some(1), None).is_none());
        assert!(crate::api::auth::decode_pchansync_claim(Some(1), Some(&"A".repeat(200))).is_none());
    }
}

#[cfg(test)]
mod erased_on_arrival_tests {
    //! Audit W-A (l2-node 0.151.0): a message erased on arrival by a pending
    //! GDPR deletion request is stored hidden — the local-submit paths (WS
    //! `Message` / `Dm` frames, `POST /dm/{address}`) must not relay it.
    use super::*;
    use crate::messages::envelope::Envelope;
    use crate::messages::types::{
        ChatMessagePayload, DeletionRequestPayload, DeletionType, DirectMessagePayload, MessageType,
    };
    use axum::response::IntoResponse;

    struct Fixture {
        state: Arc<AppState>,
        rx: tokio::sync::mpsc::UnboundedReceiver<crate::network::GossipPublish>,
        _dir: tempfile::TempDir,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = crate::storage::rocks::Storage::open(dir.path()).unwrap();
        let identity = crate::storage::identity::IdentityResolver::new(storage.clone());
        let router = crate::messages::router::MessageRouter::new(
            storage.clone(),
            identity.clone(),
            None,
            "testnet".into(),
            usize::MAX,
            Arc::new(crate::metrics::counters::NetworkCounters::new()),
            crate::config::RateLimitsConfig::default(),
        );
        let mut st = AppState::new(
            storage, router, "wsNode".into(), "testnet".into(), String::new(), String::new(), None, identity,
            None, None, None,
        );
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        st.gossip_tx = tx;
        Fixture { state: Arc::new(st), rx, _dir: dir }
    }

    fn now() -> u64 {
        crate::util::now_ms()
    }

    fn signed(sk: &ed25519_dalek::SigningKey, msg_type: MessageType, payload: Vec<u8>, ts: u64) -> Envelope {
        let msg_id = crypto::compute_msg_id("testnet", &sk.verifying_key().to_bytes(), &payload, ts);
        let sig = signing::sign_ogmara_message(
            sk, "testnet", crate::messages::envelope::PROTOCOL_VERSION, msg_type as u8, &msg_id, ts, &payload,
        );
        Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type,
            msg_id,
            author: crypto::pubkey_to_address(&sk.verifying_key()).unwrap(),
            timestamp: ts,
            lamport_ts: 0,
            payload,
            signature: sig.to_bytes().to_vec(),
            relay_path: vec![],
        }
    }

    fn chat(sk: &ed25519_dalek::SigningKey, ts: u64) -> Envelope {
        let p = ChatMessagePayload {
            channel_id: 3,
            content: format!("hello {ts}"),
            content_rating: Default::default(),
            reply_to: None,
            mentions: vec![],
            attachments: vec![],
            enc_content: None,
            enc_nonce: None,
            key_epoch: None,
            buttons: vec![],
            via_button: false,
        };
        signed(sk, MessageType::ChatMessage, rmp_serde::to_vec_named(&p).unwrap(), ts)
    }

    fn dm(sk: &ed25519_dalek::SigningKey, to: &str, ts: u64) -> Envelope {
        let from = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let p = DirectMessagePayload {
            recipient: to.to_string(),
            conversation_id: crypto::compute_conversation_id(&from, to),
            content: vec![1, 2, 3],
            nonce: [0u8; 24],
            key_epoch: 1,
            reply_to: None,
            attachments: vec![],
        };
        signed(sk, MessageType::DirectMessage, rmp_serde::to_vec_named(&p).unwrap(), ts)
    }

    /// A pending (sync-path) deletion request by `sk`'s wallet for `target`.
    fn pend(state: &AppState, sk: &ed25519_dalek::SigningKey, target: [u8; 32], ts: u64) {
        let wallet = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        state
            .storage
            .put_cf(
                crate::storage::schema::cf::USERS,
                wallet.as_bytes(),
                serde_json::json!({"address": wallet, "registered_at": 1_000}).to_string().as_bytes(),
            )
            .unwrap();
        let p = DeletionRequestPayload { delete_type: DeletionType::SingleMessage, target_id: Some(target) };
        let env = signed(sk, MessageType::DeletionRequest, rmp_serde::to_vec_named(&p).unwrap(), ts);
        assert!(matches!(
            state.router.process_synced_message(&rmp_serde::to_vec_named(&env).unwrap()),
            crate::messages::router::RouteResult::Accepted { .. }
        ));
    }

    fn published(rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::network::GossipPublish>) -> usize {
        let mut n = 0;
        while rx.try_recv().is_ok() {
            n += 1;
        }
        n
    }

    #[tokio::test]
    async fn ws_frames_do_not_relay_a_message_erased_on_arrival() {
        let mut f = fixture();
        let sk = crypto::generate_keypair();
        let wallet = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let other = crypto::pubkey_to_address(&crypto::generate_keypair().verifying_key()).unwrap();
        let t = now();
        let (erased_chat, kept_chat) = (chat(&sk, t), chat(&sk, t + 1));
        let (erased_dm, kept_dm) = (dm(&sk, &other, t + 2), dm(&sk, &other, t + 3));
        pend(&f.state, &sk, erased_chat.msg_id, t + 10);
        pend(&f.state, &sk, erased_dm.msg_id, t + 11);
        for (env, frame_dm) in [(&erased_chat, false), (&erased_dm, true)] {
            submit_ws_envelope(&f.state, &wallet, &serde_json::to_value(env).unwrap(), frame_dm).await;
            assert!(f.state.storage.is_deleted(&env.msg_id).unwrap(), "stored, erased on arrival");
            assert_eq!(published(&mut f.rx), 0, "an erased-on-arrival message is not relayed");
        }
        // Controls: ordinary messages are relayed on both frames.
        submit_ws_envelope(&f.state, &wallet, &serde_json::to_value(&kept_chat).unwrap(), false).await;
        assert_eq!(published(&mut f.rx), 1);
        submit_ws_envelope(&f.state, &wallet, &serde_json::to_value(&kept_dm).unwrap(), true).await;
        assert_eq!(published(&mut f.rx), 1);
    }

    #[tokio::test]
    async fn rest_dm_send_does_not_relay_a_dm_erased_on_arrival() {
        let mut f = fixture();
        let sk = crypto::generate_keypair();
        let wallet = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let other = crypto::pubkey_to_address(&crypto::generate_keypair().verifying_key()).unwrap();
        let t = now();
        let erased = dm(&sk, &other, t);
        pend(&f.state, &sk, erased.msg_id, t + 5);
        let auth = || Extension(crate::api::auth::AuthUser { address: wallet.clone(), signing_address: wallet.clone() });
        let res = crate::api::routes::send_dm(
            Extension(f.state.clone()),
            auth(),
            axum::extract::Path(other.clone()),
            axum::body::Bytes::from(rmp_serde::to_vec_named(&erased).unwrap()),
        )
        .await
        .into_response();
        assert!(res.status().is_success());
        assert!(f.state.storage.is_deleted(&erased.msg_id).unwrap());
        assert_eq!(published(&mut f.rx), 0, "not relayed");
        // Control: an ordinary DM is published (answer it so the handler's
        // bounded wait returns at once).
        let kept = dm(&sk, &other, t + 1);
        let state = f.state.clone();
        let handle = tokio::spawn(async move {
            crate::api::routes::send_dm(
                Extension(state),
                Extension(crate::api::auth::AuthUser { address: wallet.clone(), signing_address: wallet }),
                axum::extract::Path(other),
                axum::body::Bytes::from(rmp_serde::to_vec_named(&kept).unwrap()),
            )
            .await
            .into_response()
        });
        let p = f.rx.recv().await.expect("published");
        if let Some(tx) = p.respond_to {
            let _ = tx.send(crate::network::PublishOutcome::Propagated);
        }
        assert!(handle.await.unwrap().status().is_success());
    }
}
