//! Wallet-based authentication for the admin dashboard.
//!
//! Challenge-response flow using Klever message signing (spec 10-dashboard.md §5):
//! 1. GET /admin/auth/challenge → nonce + timestamp
//! 2. User signs challenge with Klever wallet
//! 3. POST /admin/auth/login → session token (HMAC-signed cookie)
//! 4. Subsequent requests use session cookie or Bearer token
//!
//! Localhost bypass: requests from 127.0.0.1/::1 skip auth entirely.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Extension, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::crypto;
use crate::crypto::signing;

use super::state::AppState;

/// Nonce TTL (5 minutes).
const NONCE_TTL: Duration = Duration::from_secs(300);

/// Maximum concurrent pending challenges (prevents memory exhaustion).
const MAX_PENDING_CHALLENGES: usize = 100;

/// Pending challenge nonces, keyed by nonce hex string.
struct PendingChallenge {
    nonce: String,
    timestamp_ms: u64,
    node_id: String,
    created_at: Instant,
}

/// Session token payload (HMAC-signed, not encrypted).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionPayload {
    /// Authenticated wallet address.
    address: String,
    /// When the session was issued (unix ms).
    issued_at: u64,
    /// When the session expires (unix ms).
    expires_at: u64,
}

/// Shared state for the admin auth system.
pub struct AdminAuthState {
    /// HMAC secret (random, regenerated on each node start).
    hmac_secret: [u8; 32],
    /// Pending challenge nonces (single-use, TTL-bounded).
    challenges: std::sync::Mutex<HashMap<String, PendingChallenge>>,
    /// Authorized wallet addresses (from config).
    admin_wallets: Vec<String>,
    /// Session TTL in hours.
    session_ttl_hours: u64,
    /// Node ID (included in challenge message).
    node_id: String,
}

impl AdminAuthState {
    /// Create a new auth state with a random HMAC secret.
    pub fn new(admin_wallets: Vec<String>, session_ttl_hours: u64, node_id: String) -> Self {
        let mut hmac_secret = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut hmac_secret);

        Self {
            hmac_secret,
            challenges: std::sync::Mutex::new(HashMap::new()),
            admin_wallets,
            session_ttl_hours,
            node_id,
        }
    }

    /// Check if remote auth is enabled (admin_wallets is non-empty).
    pub fn remote_auth_enabled(&self) -> bool {
        !self.admin_wallets.is_empty()
    }

    /// Generate a challenge nonce. Returns error if storage fails or limit is reached.
    fn create_challenge(&self) -> Result<(String, u64), &'static str> {
        let mut nonce_bytes = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        let timestamp_ms = now_ms();

        let mut challenges = self.challenges.lock().map_err(|e| {
            warn!("Challenge mutex poisoned: {}", e);
            "internal server error"
        })?;

        // Prune expired challenges
        challenges.retain(|_, c| c.created_at.elapsed() < NONCE_TTL);

        // Enforce limit — return error so the client knows why
        if challenges.len() >= MAX_PENDING_CHALLENGES {
            return Err("too many pending challenges, try again later");
        }

        challenges.insert(
            nonce.clone(),
            PendingChallenge {
                nonce: nonce.clone(),
                timestamp_ms,
                node_id: self.node_id.clone(),
                created_at: Instant::now(),
            },
        );

        Ok((nonce, timestamp_ms))
    }

    /// Validate and consume a challenge nonce. Returns the challenge message that was signed.
    fn consume_challenge(&self, nonce: &str) -> Option<String> {
        let challenge = {
            let mut challenges = match self.challenges.lock() {
                Ok(c) => c,
                Err(e) => {
                    warn!("Challenge mutex poisoned on consume: {}", e);
                    return None;
                }
            };
            challenges.remove(nonce)?
        };

        // Check TTL
        if challenge.created_at.elapsed() > NONCE_TTL {
            return None;
        }

        // Build the challenge message that was signed
        Some(format!(
            "Ogmara Dashboard Login\nNode: {}\nNonce: {}\nTimestamp: {}",
            challenge.node_id, challenge.nonce, challenge.timestamp_ms
        ))
    }

    /// Verify a wallet address is in the admin list.
    fn is_admin_wallet(&self, address: &str) -> bool {
        self.admin_wallets.iter().any(|w| w == address)
    }

    /// Create an HMAC-signed session token.
    fn create_session_token(&self, address: &str) -> String {
        let now = now_ms();
        let expires = now + self.session_ttl_hours * 3600 * 1000;

        let payload = SessionPayload {
            address: address.to_string(),
            issued_at: now,
            expires_at: expires,
        };

        let payload_json = serde_json::to_string(&payload).unwrap_or_default();
        let payload_b64 = base64_encode(payload_json.as_bytes());
        let sig = self.hmac_sign(payload_b64.as_bytes());
        let sig_b64 = base64_encode(&sig);

        format!("{}.{}", payload_b64, sig_b64)
    }

    /// Verify a session token and return the address if valid.
    fn verify_session_token(&self, token: &str) -> Option<String> {
        let parts: Vec<&str> = token.splitn(2, '.').collect();
        if parts.len() != 2 {
            return None;
        }

        let payload_b64 = parts[0];
        let sig_b64 = parts[1];

        // Verify HMAC
        let sig = base64_decode(sig_b64)?;
        let expected = self.hmac_sign(payload_b64.as_bytes());
        if !constant_time_eq(&sig, &expected) {
            return None;
        }

        // Decode payload
        let payload_bytes = base64_decode(payload_b64)?;
        let payload: SessionPayload = serde_json::from_slice(&payload_bytes).ok()?;

        // Check expiry
        if now_ms() > payload.expires_at {
            return None;
        }

        Some(payload.address)
    }

    /// HMAC-SHA256 using the node's secret.
    fn hmac_sign(&self, data: &[u8]) -> Vec<u8> {
        use sha2::Sha256;
        use hmac::{Hmac, Mac};

        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(&self.hmac_secret).expect("HMAC accepts any key size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
}

// ── Route Handlers ──────────────────────────────────────────────────

/// GET /admin/auth/challenge — generate a challenge nonce for wallet login.
pub async fn auth_challenge(
    Extension(auth_state): Extension<Arc<AdminAuthState>>,
) -> impl IntoResponse {
    match auth_state.create_challenge() {
        Ok((nonce, timestamp)) => Json(serde_json::json!({
            "nonce": nonce,
            "timestamp": timestamp,
            "node_id": auth_state.node_id,
        })).into_response(),
        Err(msg) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": msg
        }))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    /// Klever wallet address (klv1...).
    pub address: String,
    /// Base64-encoded Ed25519 signature of the challenge message.
    pub signature: String,
    /// The challenge nonce (from /admin/auth/challenge).
    pub nonce: String,
}

/// POST /admin/auth/login — verify signed challenge and issue session token.
pub async fn auth_login(
    Extension(auth_state): Extension<Arc<AdminAuthState>>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    // 1. Consume the nonce (single-use)
    let challenge_msg = match auth_state.consume_challenge(&req.nonce) {
        Some(msg) => msg,
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "invalid or expired nonce"
            }))).into_response();
        }
    };

    // 2. Check address is in admin_wallets
    if !auth_state.is_admin_wallet(&req.address) {
        warn!(address = %req.address, "Dashboard login attempt from non-admin wallet");
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({
            "error": "wallet not authorized"
        }))).into_response();
    }

    // 3. Decode signature
    let sig_bytes = match base64_decode(&req.signature) {
        Some(bytes) if bytes.len() == 64 => bytes,
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "invalid signature format"
            }))).into_response();
        }
    };

    let signature = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "invalid signature bytes"
            }))).into_response();
        }
    };

    // 4. Resolve verifying key from address
    let verifying_key = match crypto::address_to_verifying_key(&req.address) {
        Ok(key) => key,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": "invalid address"
            }))).into_response();
        }
    };

    // 5. Verify signature against the challenge message (Klever message signing format)
    if signing::verify_klever_message(
        &verifying_key,
        challenge_msg.as_bytes(),
        &signature,
    ).is_err() {
        warn!(address = %req.address, "Dashboard login signature verification failed");
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
            "error": "signature verification failed"
        }))).into_response();
    }

    // 6. Issue session token
    let token = auth_state.create_session_token(&req.address);

    debug!(address = %req.address, "Dashboard login successful");

    // Set HttpOnly cookie + return token in body
    // Use SameSite=Lax (not Strict) so the cookie works on initial navigation
    // from external links. Secure flag ensures HTTPS-only in production.
    let cookie = format!(
        "ogmara_session={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}; Secure",
        token,
        auth_state.session_ttl_hours * 3600
    );

    let mut response = Json(serde_json::json!({
        "session_token": token,
        "address": req.address,
        "expires_in_hours": auth_state.session_ttl_hours,
    })).into_response();

    if let Ok(cookie_val) = cookie.parse() {
        response.headers_mut().insert(axum::http::header::SET_COOKIE, cookie_val);
    }

    response
}

/// POST /admin/auth/logout — clear session cookie.
pub async fn auth_logout() -> impl IntoResponse {
    let cookie = "ogmara_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0; Secure";

    let mut response = Json(serde_json::json!({ "ok": true })).into_response();
    if let Ok(cookie_val) = cookie.parse() {
        response.headers_mut().insert(axum::http::header::SET_COOKIE, cookie_val);
    }

    response
}

// ── Admin Auth Middleware ────────────────────────────────────────────

/// Middleware that allows access from localhost (no auth) or with a valid
/// session token (for remote access via admin_wallets).
///
/// Supports `X-Forwarded-For` header for reverse proxy deployments (Apache, nginx).
/// When behind a proxy, the TCP peer is always 127.0.0.1 — this header reveals the
/// real client IP so the localhost bypass only applies to actual local access.
pub async fn admin_auth_middleware(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Extension(auth_state): Extension<Arc<AdminAuthState>>,
    req: Request,
    next: Next,
) -> Response {
    // Determine real client IP: X-Forwarded-For (first entry) if present, else TCP peer.
    // Only trust X-Forwarded-For when the TCP peer is loopback (i.e., request came from
    // a local reverse proxy). If TCP peer is remote, ignore the header (could be spoofed).
    let real_ip_is_loopback = if addr.ip().is_loopback() {
        // Check if a reverse proxy forwarded this from a remote client
        match req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            Some(forwarded) => {
                // X-Forwarded-For: client, proxy1, proxy2 — first entry is the original client
                let client_ip = forwarded.split(',').next().unwrap_or("").trim();
                match client_ip.parse::<std::net::IpAddr>() {
                    Ok(ip) => ip.is_loopback(),
                    Err(_) => false, // unparseable → treat as remote (require auth)
                }
            }
            None => true, // No proxy header, TCP peer is loopback → genuine localhost
        }
    } else {
        false
    };

    // Localhost always passes (spec 10-dashboard.md §5.6)
    if real_ip_is_loopback {
        return next.run(req).await;
    }

    // If no admin_wallets configured, reject remote access
    if !auth_state.remote_auth_enabled() {
        return (StatusCode::FORBIDDEN, "admin endpoints are localhost-only").into_response();
    }

    // Check for session token in cookie or Authorization header
    let token = extract_session_token(&req);

    match token {
        Some(t) => {
            match auth_state.verify_session_token(&t) {
                Some(_address) => next.run(req).await,
                None => (StatusCode::UNAUTHORIZED, "invalid or expired session").into_response(),
            }
        }
        None => (StatusCode::UNAUTHORIZED, "authentication required").into_response(),
    }
}

/// Extract session token from cookie or Authorization header.
fn extract_session_token(req: &Request) -> Option<String> {
    // Try Authorization: Bearer <token>
    if let Some(auth) = req.headers().get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            return Some(token.to_string());
        }
    }

    // Try ogmara_session cookie
    if let Some(cookie_header) = req.headers().get("cookie").and_then(|v| v.to_str().ok()) {
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some(token) = cookie.strip_prefix("ogmara_session=") {
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
    }

    None
}

// ── Helpers ─────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_decode(data: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data).ok()
}

/// Constant-time equality comparison to prevent timing attacks on tokens.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
