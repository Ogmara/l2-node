//! Rate-limit key extractor that resolves the real client IP behind a
//! reverse proxy (v0.48.6).
//!
//! `tower_governor`'s default `PeerIpKeyExtractor` keys on the TCP peer
//! IP. Behind a reverse proxy (Apache `mod_proxy`, nginx) the peer is
//! always the proxy, so **every** client shares one rate-limit bucket —
//! the proxy's IP. On the production darkw0rld node (Apache-fronted,
//! ~13 active users) this saturated the shared default 100/min bucket
//! and returned `429 Too Many Requests! Wait for 0s` to every request,
//! including login, even though no individual client was close to the
//! limit.
//!
//! This extractor instead resolves the true client IP with the **same**
//! [`resolve_client_ip`] logic `admin_auth` already uses: it honours
//! `X-Forwarded-For` / RFC 7239 `Forwarded` **only** when the peer is a
//! trusted proxy (loopback is always trusted; others via
//! `api.trusted_proxies`), walking the chain right-to-left so an
//! untrusted client cannot spoof its IP to dodge the limit. With it,
//! `rate_limit_per_ip` means *per real client* again even behind a
//! proxy, and an untrusted direct peer still keys on its own IP exactly
//! like the built-in extractor.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::http::header::FORWARDED;
use axum::http::Request;
use tower_governor::errors::GovernorError;
use tower_governor::key_extractor::KeyExtractor;

use crate::trusted_proxies::{resolve_client_ip, TrustedProxies};

/// `X-Forwarded-For` header name (lowercase; `HeaderMap` lookup is
/// case-insensitive). `http` has no constant for this de-facto header.
const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Key extractor that resolves the real client IP via the node's
/// trusted-proxy configuration. Cheap to clone (`Arc` inside) — the
/// governor layer clones it per request.
#[derive(Clone)]
pub struct TrustedProxyIpKeyExtractor {
    trusted: Arc<TrustedProxies>,
}

impl TrustedProxyIpKeyExtractor {
    pub fn new(trusted: Arc<TrustedProxies>) -> Self {
        Self { trusted }
    }
}

impl KeyExtractor for TrustedProxyIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        // Peer socket from axum `ConnectInfo` — the same source the
        // built-in `PeerIpKeyExtractor` reads (wired via
        // `into_make_service_with_connect_info::<SocketAddr>()`). If it's
        // absent we cannot rate-limit by IP, so surface the identical
        // error the built-in does rather than silently global-limiting.
        let peer = req
            .extensions()
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0)
            .ok_or(GovernorError::UnableToExtractKey)?;

        let forwarded = req
            .headers()
            .get(FORWARDED)
            .and_then(|v| v.to_str().ok());
        let xff = req
            .headers()
            .get(X_FORWARDED_FOR)
            .and_then(|v| v.to_str().ok());

        // resolve_client_ip ignores the headers unless `peer` is
        // loopback or a configured trusted proxy — the security anchor
        // that stops an untrusted client from spoofing its key.
        Ok(resolve_client_ip(peer, forwarded, xff, &self.trusted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::ConnectInfo;

    fn req_with(peer: &str, xff: Option<&str>) -> Request<()> {
        let mut req = Request::new(());
        req.extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        if let Some(v) = xff {
            req.headers_mut()
                .insert(X_FORWARDED_FOR, v.parse().unwrap());
        }
        req
    }

    fn extractor(proxies: &[&str]) -> TrustedProxyIpKeyExtractor {
        let tp = TrustedProxies::from_strings(
            &proxies.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        TrustedProxyIpKeyExtractor::new(Arc::new(tp))
    }

    #[test]
    fn loopback_peer_keys_on_real_client_from_xff() {
        // The Apache-on-localhost case: peer is loopback (auto-trusted),
        // so the real client behind XFF gets its own bucket.
        let ex = extractor(&[]);
        let key = ex
            .extract(&req_with("127.0.0.1:5555", Some("203.0.113.7")))
            .unwrap();
        assert_eq!(key, "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn two_clients_behind_proxy_get_distinct_keys() {
        // The whole point of the fix: distinct real clients behind the
        // same proxy no longer share a bucket.
        let ex = extractor(&[]);
        let a = ex
            .extract(&req_with("127.0.0.1:5555", Some("203.0.113.7")))
            .unwrap();
        let b = ex
            .extract(&req_with("127.0.0.1:5555", Some("203.0.113.8")))
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn untrusted_peer_keys_on_peer_ignoring_xff() {
        // Security anchor: a direct (untrusted) client cannot spoof XFF
        // to escape its own limit.
        let ex = extractor(&[]);
        let key = ex
            .extract(&req_with("8.8.8.8:5555", Some("203.0.113.7")))
            .unwrap();
        assert_eq!(key, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn missing_connect_info_errors_like_builtin() {
        let ex = extractor(&[]);
        let req = Request::new(()); // no ConnectInfo extension
        assert!(matches!(
            ex.extract(&req),
            Err(GovernorError::UnableToExtractKey)
        ));
    }
}
