//! Authentication middleware for Klever wallet signature verification.
//!
//! Authenticated endpoints require three headers (spec 4.2):
//!   X-Ogmara-Auth:      base64(Ed25519 signature)
//!   X-Ogmara-Address:   klv1... Klever address
//!   X-Ogmara-Timestamp: unix timestamp in milliseconds
//!
//! Auth string: "ogmara-auth:{timestamp}:{method}:{path}"
//! Signed using Klever message signing format (protocol spec 4.1.1).

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::crypto;
use crate::crypto::signing;

/// Maximum age for an auth header timestamp (60 seconds).
const MAX_AUTH_AGE_MS: u64 = 60_000;

/// Authenticated user info extracted from headers.
#[derive(Debug, Clone)]
pub struct AuthUser {
    /// Klever address of the authenticated user.
    pub address: String,
}

/// Axum middleware that verifies Klever wallet signature auth headers.
pub async fn auth_middleware(mut req: Request, next: Next) -> Response {
    match extract_and_verify(&req) {
        Ok(user) => {
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        Err(msg) => (StatusCode::UNAUTHORIZED, msg).into_response(),
    }
}

/// Extract and verify auth headers from the request.
fn extract_and_verify(req: &Request) -> Result<AuthUser, String> {
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
        .map_err(|e| format!("invalid address: {}", e))?;

    // Build the auth string and verify
    let method = req.method().as_str();
    let path = req.uri().path();

    signing::verify_auth_header(&verifying_key, timestamp, method, path, &signature)
        .map_err(|_| "signature verification failed")?;

    Ok(AuthUser {
        address: address.to_string(),
    })
}
