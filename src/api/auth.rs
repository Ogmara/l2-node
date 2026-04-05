//! Authentication middleware for Klever wallet signature verification.
//!
//! Authenticated endpoints require three headers (spec 4.2):
//!   X-Ogmara-Auth:      base64(Ed25519 signature)
//!   X-Ogmara-Address:   klv1... (wallet) or ogd1... (device) address
//!   X-Ogmara-Timestamp: unix timestamp in milliseconds
//!
//! Auth string: "ogmara-auth:{timestamp}:{method}:{path}"
//! Signed using Klever message signing format (protocol spec 4.1.1).
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

/// Maximum age for an auth header timestamp (60 seconds).
const MAX_AUTH_AGE_MS: u64 = 60_000;

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

    match extract_and_verify(&req, &app_state) {
        Ok(user) => {
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

    if let Ok(user) = extract_and_verify(&req, &app_state) {
        req.extensions_mut().insert(user);
    }
    next.run(req).await
}

/// Extract and verify auth headers, then resolve device → wallet.
fn extract_and_verify(req: &Request, app_state: &AppState) -> Result<AuthUser, String> {
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

    // Parse timestamp
    let timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| "invalid timestamp format")?;

    // Check timestamp freshness
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let age = if now_ms > timestamp {
        now_ms - timestamp
    } else {
        timestamp - now_ms
    };

    if age > MAX_AUTH_AGE_MS {
        return Err("auth timestamp expired or too far in future".to_string());
    }

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

    // Build the auth string and verify signature against the device key
    let method = req.method().as_str();
    let path = req.uri().path();

    signing::verify_auth_header(&verifying_key, timestamp, method, path, &signature)
        .map_err(|e| {
            tracing::warn!(
                address = %address,
                method = %method,
                path = %path,
                timestamp = %timestamp,
                error = %e,
                "Auth signature verification failed"
            );
            "signature verification failed".to_string()
        })?;

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

    Ok(AuthUser {
        address: resolved_address,
        signing_address,
    })
}
