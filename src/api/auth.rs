//! Authentication middleware for Klever wallet signature verification.
//!
//! Authenticated endpoints require four headers (spec 4.2):
//!   X-Ogmara-Auth:      base64(Ed25519 signature)
//!   X-Ogmara-Address:   klv1... (wallet) or ogd1... (device) address
//!   X-Ogmara-Timestamp: unix timestamp in milliseconds
//!   X-Ogmara-Nonce:     client-chosen single-use nonce (hex)
//!
//! Auth string (v2, audit 2026-06-07 host-binding):
//!   "ogmara-auth:{network}:{node_id}:{nonce}:{timestamp}:{method}:{path}"
//! Signed using Klever message signing format (protocol spec 4.1.1).
//!
//! `network` + `node_id` are the *verifying node's own* values — a
//! signature captured for one node fails on any other node (different
//! node_id) or network, defeating cross-node replay. The single-use
//! `nonce`, tracked in `AppState::auth_nonce_seen` for the freshness
//! window, defeats same-node replay.
//!
//! After signature verification, the middleware resolves the signing address
//! (device key) to its owning wallet address via the IdentityResolver.
//! If no mapping exists, the signing address IS the wallet (built-in wallet mode).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::crypto;
use crate::crypto::signing;

use super::state::AppState;

/// Maximum age for an auth header timestamp in the past (60 seconds).
pub const MAX_AUTH_AGE_MS: u64 = 60_000;

/// Maximum tolerated clock skew into the future (5 seconds). Tighter than
/// the past window (audit 2026-06-07 W1): a legitimate client's clock may
/// lag behind ours by up to a minute, but a request stamped far in the
/// *future* is either a badly-skewed client or a pre-minted replay token,
/// neither of which we want to honour for a full minute.
pub const MAX_AUTH_FUTURE_SKEW_MS: u64 = 5_000;

/// Bounds on the client-supplied nonce length (hex chars). Long enough to
/// be collision-free (16 bytes = 32 hex), capped so a hostile client can't
/// bloat the replay cache key.
const MIN_NONCE_LEN: usize = 16;
const MAX_NONCE_LEN: usize = 128;

/// Authenticated user info extracted from headers and identity resolution.
#[derive(Debug, Clone)]
pub struct AuthUser {
    /// Resolved wallet address — the user's on-chain identity.
    /// All storage/indexing uses this address.
    pub address: String,
    /// The address that signed this request — either a wallet (klv1...)
    /// or a delegated device key (ogd1...).
    /// May be the same as `address` for built-in wallets.
    pub signing_address: String,
}

/// Axum middleware that verifies Klever wallet signature auth headers
/// and resolves the signing device to its owning wallet.
pub async fn auth_middleware(mut req: Request, next: Next) -> Response {
    // Extract AppState for identity resolution
    let app_state = match req.extensions().get::<Arc<AppState>>() {
        Some(state) => state.clone(),
        None => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "missing app state").into_response();
        }
    };

    // `extract_and_verify` is SYNC (signature check) so nothing borrowing the
    // request — whose `Body` is `!Sync` — is held across an `.await`, which would
    // make this middleware future `!Send` and break `middleware::from_fn`. The
    // single async step (the nonce-replay claim) runs here over OWNED values.
    match extract_and_verify(&req, &app_state) {
        Ok((user, nonce)) => {
            if let Err(msg) = claim_nonce(&app_state, &user.signing_address, &nonce).await {
                return (StatusCode::UNAUTHORIZED, msg).into_response();
            }
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        Err(msg) => (StatusCode::UNAUTHORIZED, msg).into_response(),
    }
}

/// Optional auth middleware — inserts AuthUser into extensions if valid auth
/// headers are present, but passes through without error if missing/invalid.
/// Used on public routes that optionally benefit from knowing the caller.
pub async fn optional_auth_middleware(mut req: Request, next: Next) -> Response {
    let app_state = match req.extensions().get::<Arc<AppState>>() {
        Some(state) => state.clone(),
        None => return next.run(req).await,
    };

    // Best-effort: verify (sync) then burn the nonce (async, owned values). A
    // replayed nonce on an optional-auth route simply isn't treated as
    // authenticated. Owned-values-only across the await keeps the future Send.
    if let Ok((user, nonce)) = extract_and_verify(&req, &app_state) {
        if claim_nonce(&app_state, &user.signing_address, &nonce).await.is_ok() {
            req.extensions_mut().insert(user);
        }
    }
    next.run(req).await
}

/// Validate the freshness of an auth timestamp against the local clock.
///
/// Allows up to `MAX_AUTH_AGE_MS` in the past and only `MAX_AUTH_FUTURE_SKEW_MS`
/// in the future (audit 2026-06-07 W1 — asymmetric skew). Shared by the REST
/// and WebSocket verifiers.
pub fn check_timestamp_fresh(timestamp: u64) -> Result<(), String> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    if timestamp > now_ms {
        if timestamp - now_ms > MAX_AUTH_FUTURE_SKEW_MS {
            return Err("auth timestamp too far in future".to_string());
        }
    } else if now_ms - timestamp > MAX_AUTH_AGE_MS {
        return Err("auth timestamp expired".to_string());
    }
    Ok(())
}

/// Validate a client-supplied nonce: bounded length, hex characters only.
pub fn validate_nonce(nonce: &str) -> Result<(), String> {
    if nonce.len() < MIN_NONCE_LEN || nonce.len() > MAX_NONCE_LEN {
        return Err("invalid nonce length".to_string());
    }
    if !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("nonce must be hex".to_string());
    }
    Ok(())
}

/// Record a `(signing_address, nonce)` as used; reject if already seen.
/// Closes the same-node replay window (audit 2026-06-07). The check and
/// insert are not a single atomic op, but the only race is two *simultaneous*
/// first-uses of the same nonce — which gains an attacker nothing; the point
/// is to block any *later* replay, and the later replay always sees the entry.
pub async fn claim_nonce(
    app_state: &AppState,
    signing_address: &str,
    nonce: &str,
) -> Result<(), String> {
    let key = format!("{signing_address}:{nonce}");
    if app_state.auth_nonce_seen.get(&key).await.is_some() {
        return Err("auth nonce already used (replay rejected)".to_string());
    }
    app_state.auth_nonce_seen.insert(key, ()).await;
    Ok(())
}

/// Extract and verify auth headers, then resolve device → wallet.
///
/// SYNC by design: it must not `.await` while borrowing `req` (whose `Body` is
/// `!Sync`), or the calling middleware future becomes `!Send` and
/// `middleware::from_fn` won't accept it. Returns the resolved `AuthUser` plus
/// the request's `nonce` (owned) so the caller can do the async replay-claim
/// (`claim_nonce`) over owned values.
fn extract_and_verify(req: &Request, app_state: &AppState) -> Result<(AuthUser, String), String> {
    let headers = req.headers();

    // Extract required headers
    let auth_b64 = headers
        .get("x-ogmara-auth")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing X-Ogmara-Auth header")?;

    let address = headers
        .get("x-ogmara-address")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing X-Ogmara-Address header")?;

    let timestamp_str = headers
        .get("x-ogmara-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing X-Ogmara-Timestamp header")?;

    let nonce = headers
        .get("x-ogmara-nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing X-Ogmara-Nonce header")?;
    validate_nonce(nonce)?;

    // Parse timestamp
    let timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| "invalid timestamp format")?;

    // Check timestamp freshness (asymmetric past/future skew).
    check_timestamp_fresh(timestamp)?;

    // Decode signature from base64
    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        auth_b64,
    )
    .map_err(|_| "invalid base64 in X-Ogmara-Auth")?;

    if sig_bytes.len() != 64 {
        return Err("signature must be 64 bytes".to_string());
    }

    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|_| "invalid Ed25519 signature bytes")?;

    // Resolve the verifying key from the Klever address
    let verifying_key = crypto::address_to_verifying_key(address)
        .map_err(|_| "invalid address".to_string())?;

    // Build the auth string and verify signature against the device key.
    // `network` + `node_id` are THIS node's own values — that's what binds
    // the signature to this node and defeats cross-node replay.
    let method = req.method().as_str();
    let path = req.uri().path();
    let network = app_state.klever_network.as_str();
    let node_id = app_state.node_id.as_str();

    signing::verify_auth_header(
        &verifying_key, network, node_id, nonce, timestamp, method, path, &signature,
    )
    .map_err(|e| {
        tracing::warn!(
            address = %address,
            method = %method,
            path = %path,
            timestamp = %timestamp,
            network = %network,
            node_id = %node_id,
            error = %e,
            "Auth signature verification failed"
        );
        "signature verification failed".to_string()
    })?;

    // NOTE: the nonce replay-claim (`claim_nonce`) is done by the async caller
    // over owned values — see `auth_middleware` — to keep this fn sync (and the
    // middleware future `Send`).

    // Resolve device address → wallet address.
    // If no mapping exists, the signing address IS the wallet (built-in wallet mode).
    let signing_address = address.to_string();
    let resolved_address = app_state
        .identity
        .resolve(address)
        .map_err(|e| {
            tracing::error!(
                signing_address = %address,
                error = %e,
                "Identity resolution failed"
            );
            "identity resolution error".to_string()
        })?;

    // P-1 (identity-sync): the first time this wallet/device is seen on this
    // node, lazily pull its identity bundle (delegation/profile/follows) from
    // peers so the user keeps their identity, follows, and feed wherever they
    // connect. The network task dedups per subject per session, so firing per
    // request is cheap; `let _ =` ignores a closed channel (network task gone).
    // An unresolved device (`resolved_address` still `ogd1…`) is resolved to
    // its wallet by the serving peer, whose returned delegation then lets us
    // resolve the device locally.
    let _ = app_state
        .identity_sync_tx
        .send(crate::network::IdentitySyncCommand {
            wallet: resolved_address.clone(),
            scopes: crate::network::identity_sync::SCOPE_ALL,
        });

    Ok((
        AuthUser {
            address: resolved_address,
            signing_address,
        },
        nonce.to_string(),
    ))
}
