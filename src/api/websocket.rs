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
}

/// The fixed path the WS auth signature is bound to.
const WS_AUTH_PATH: &str = "/api/v1/ws";

/// Verify a WebSocket auth message (same scheme as REST auth headers).
///
/// Binds `network` + `node_id` (this node's own) and a single-use `nonce`
/// exactly like the REST verifier (audit 2026-06-07 host-binding), so a
/// captured WS-auth frame is neither fleet-portable nor same-node replayable.
async fn verify_ws_auth(text: &str, state: &AppState) -> Result<String, String> {
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

    Ok(auth.address)
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
    Message { envelope: serde_json::Value },
    Dm { envelope: serde_json::Value },
    Notification { mention: serde_json::Value },
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
    let auth_address = match auth_result {
        Ok(addr) => {
            debug!(address = %addr, "WebSocket client authenticated");
            addr
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

    // Subscribe this node to the user's DM gossip topic so DMs sent to them from
    // OTHER nodes are received and indexed here (the network task owns the swarm).
    // Idempotent in the topic layer; safe to send on every connect.
    let _ = state.dm_subscribe_tx.send(wallet_address.clone());

    // Register this user with the notification engine for mention detection
    if let Some(ref engine) = state.notification_engine {
        engine.add_local_user(&wallet_address).await;
    }

    // Subscribe to broadcast channel for forwarding messages
    let mut broadcast_rx = state.ws_broadcast.subscribe();

    // Process messages in both directions
    loop {
        tokio::select! {
            // Forward broadcast messages to client
            Ok(msg) = broadcast_rx.recv() => {
                if sender.send(Message::Text(msg.into())).await.is_err() {
                    break;
                }
            }
            // Handle client messages
            client_msg = receiver.next() => {
                match client_msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Err(e) = handle_ws_client_message(&text, &state, &mut sender).await {
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
            // Process through message router
            if let Ok(bytes) = rmp_serde::to_vec(&envelope) {
                let result = state.router.process_message(&bytes);
                debug!(result = ?result, "WS message processed");
                // Feed accepted messages to notification engine for mention detection
                if let crate::messages::router::RouteResult::Accepted { raw_bytes, .. } = result {
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
        }
        WsClientMessage::Dm { envelope } => {
            if let Ok(bytes) = rmp_serde::to_vec(&envelope) {
                let result = state.router.process_message(&bytes);
                debug!(result = ?result, "WS DM processed");
            }
        }
    }

    Ok(())
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
            Ok(msg) = broadcast_rx.recv() => {
                if sender.send(Message::Text(msg.into())).await.is_err() {
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
