//! Trusted-proxy IP resolution (v0.42).
//!
//! Determines the real client IP behind a chain of forwarding proxies
//! using the standard pattern from Nginx `ngx_http_realip_module` and
//! Apache `mod_remoteip`:
//!
//!   1. If the immediate TCP peer is NOT trusted, ignore all
//!      forwarding headers and use the peer. This is the security
//!      anchor — without it, any client can self-set `X-Forwarded-For`
//!      and impersonate any IP.
//!   2. If the peer IS trusted, walk the forwarding chain
//!      **right-to-left**, skipping addresses that are themselves
//!      trusted proxies. The first untrusted address encountered is
//!      the real client (or the closest non-spoofable intermediate).
//!      If the entire chain is trusted, fall back to the peer.
//!
//! ## Why right-to-left, not "leftmost"
//!
//! Pre-v0.42 the L2 node used a leftmost-trust scheme: with a
//! loopback peer, take XFF's first comma-separated entry. This worked
//! for the common single-Apache-on-localhost setup, but it's only
//! safe if EVERY intermediate proxy is trustworthy. A malicious
//! intermediate (or a chained CDN whose IPs aren't in the trust set)
//! could fabricate the leftmost entry and impersonate any IP.
//!
//! Right-to-left walk is strictly more secure: the attacker can only
//! influence the entries to the right of where the trust chain
//! breaks. If your trust set lists every legitimate proxy, the walk
//! converges on the real client; if your trust set is short, the
//! walk returns a closer-to-truth intermediate IP that the attacker
//! cannot forge.
//!
//! ## Configuration
//!
//! Operators set `api.trusted_proxies` to a list of IPs or CIDRs.
//! Loopback (127.0.0.0/8, ::1) is ALWAYS implicitly trusted —
//! same-host reverse proxies are the most common setup and shouldn't
//! require explicit configuration. To extend trust to a CDN or a
//! shared-network proxy, add the CIDR (e.g. `"173.245.48.0/20"`).
//!
//! ## Headers consulted
//!
//! - **RFC 7239 `Forwarded`** — preferred. The leftmost `for=`
//!   element after the trust walk is the candidate.
//! - **`X-Forwarded-For`** — fallback. Comma-separated, leftmost is
//!   the alleged client.
//!
//! The forwarding chain is the LIST of addresses, in chain order
//! (leftmost = original client, rightmost = closest to us). The
//! walk reverses that.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, Result};

/// A single trusted-proxy entry: either a single IP (host) or a CIDR
/// block. Parsed once at config-load time and matched against the
/// peer / chain IPs on every request — keep this allocation-free.
#[derive(Debug, Clone)]
pub struct TrustedProxy {
    network: IpAddr,
    prefix_len: u8,
}

impl TrustedProxy {
    /// Parse a CIDR string (e.g. `"10.0.0.0/8"`, `"2001:db8::/32"`,
    /// `"192.0.2.5"`, `"::1"`). Bare addresses are treated as `/32`
    /// (IPv4) or `/128` (IPv6) host entries.
    pub fn parse(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("empty trusted-proxy entry"));
        }
        let (addr_part, prefix_part) = match trimmed.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (trimmed, None),
        };
        let network: IpAddr = addr_part
            .parse()
            .map_err(|e| anyhow!("invalid IP \"{}\": {}", addr_part, e))?;
        let max_prefix = match network {
            IpAddr::V4(_) => 32u8,
            IpAddr::V6(_) => 128u8,
        };
        let prefix_len: u8 = match prefix_part {
            None => max_prefix,
            Some(p) => p
                .parse::<u8>()
                .map_err(|e| anyhow!("invalid prefix \"{}\": {}", p, e))?,
        };
        if prefix_len > max_prefix {
            return Err(anyhow!(
                "prefix /{} exceeds maximum /{} for {}",
                prefix_len,
                max_prefix,
                if matches!(network, IpAddr::V4(_)) { "IPv4" } else { "IPv6" }
            ));
        }
        Ok(Self { network, prefix_len })
    }

    /// Return true if `ip` falls inside this CIDR block. IPv4-mapped
    /// IPv6 addresses (`::ffff:a.b.c.d`) are normalized to IPv4
    /// before matching, so a trust entry of `"127.0.0.0/8"` covers
    /// both native IPv4 loopback and the dual-stack form.
    pub fn matches(&self, ip: IpAddr) -> bool {
        // Normalize IPv4-mapped IPv6 to IPv4 for matching. Dual-stack
        // listeners deliver IPv4 connections as `::ffff:a.b.c.d`;
        // operator config naturally uses `1.2.3.4/24` style, so we
        // must canonicalize the input.
        let canon_ip = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => ip,
            },
            _ => ip,
        };
        match (self.network, canon_ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                prefix_match_v4(net, addr, self.prefix_len)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                prefix_match_v6(net, addr, self.prefix_len)
            }
            // Cross-family entries never match. An operator who needs
            // to cover both V4 and V6 must list both CIDRs.
            _ => false,
        }
    }
}

fn prefix_match_v4(net: Ipv4Addr, ip: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    // Mask = high `prefix` bits set. `u32::MAX << (32-prefix)` is the
    // standard formula; the (prefix == 32) branch avoids the
    // undefined-behavior of shifting by 32 on a u32.
    let mask: u32 = if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

fn prefix_match_v6(net: Ipv6Addr, ip: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u128 = if prefix >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(net) & mask) == (u128::from(ip) & mask)
}

/// Collection of trusted-proxy entries. Cheap to clone (Arc'd by the
/// caller) and to query (linear scan over a typically small list).
#[derive(Debug, Default, Clone)]
pub struct TrustedProxies {
    entries: Vec<TrustedProxy>,
}

impl TrustedProxies {
    /// Build from a list of CIDR strings (the `api.trusted_proxies`
    /// config field). Returns an error on the first malformed entry
    /// — fail-fast at startup, never silently drop a misparsed CIDR
    /// because that would degrade to "trust nothing extra" (i.e.
    /// silently flip the security model).
    pub fn from_strings(items: &[String]) -> Result<Self> {
        let mut entries = Vec::with_capacity(items.len());
        for s in items {
            entries.push(TrustedProxy::parse(s)?);
        }
        Ok(Self { entries })
    }

    /// True if `ip` is a configured trusted proxy. Loopback is NOT
    /// auto-trusted here — callers add loopback trust explicitly via
    /// `is_loopback_canonical` because that's a separate, always-on
    /// trust source.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.entries.iter().any(|e| e.matches(ip))
    }

    /// Number of configured entries. Exposed for ops/metrics.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the entry list is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Loopback detection that handles the IPv4-mapped IPv6 form
/// (`::ffff:127.0.0.1`). Centralized here so the IP-resolution path
/// has a single source of truth; `routes.rs` calls this via the
/// re-export.
pub fn is_loopback_canonical(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| v4.is_loopback())
            .unwrap_or_else(|| v6.is_loopback()),
    }
}

/// Maximum forwarding-chain length to parse from `X-Forwarded-For`
/// or `Forwarded` (v0.42 audit hardening). 32 hops is two orders of
/// magnitude beyond any legitimate CDN → reverse-proxy → origin
/// chain; a single trusted proxy that was compromised (or a
/// malicious upstream that the operator forgot to remove from
/// `trusted_proxies`) could otherwise append thousands of entries
/// to inflate per-request CPU. With this cap the parser is
/// O(min(N, 32)) instead of O(N), bounding worst-case work
/// regardless of header length.
const MAX_CHAIN_HOPS: usize = 32;

/// Parse an `X-Forwarded-For` header value into an ordered list of
/// IPs (leftmost = original client, rightmost = closest hop).
/// Malformed entries are skipped silently — XFF is famously messy
/// in the wild, and rejecting the whole header on one bad entry
/// would create a denial-of-service against clients with quirky
/// upstream proxies.
///
/// At most `MAX_CHAIN_HOPS` entries are parsed; anything past that
/// is dropped to bound worst-case work under adversarial-length
/// headers.
pub fn parse_xff(value: &str) -> Vec<IpAddr> {
    value
        .split(',')
        .take(MAX_CHAIN_HOPS)
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect()
}

/// Parse an RFC 7239 `Forwarded` header value into an ordered list
/// of IPs from the `for=` parameter of each element. Same ordering
/// convention as `parse_xff`: leftmost = original client.
///
/// Format reminder:
/// ```text
/// Forwarded: for=192.0.2.43
/// Forwarded: for="[2001:db8:cafe::17]:4711"
/// Forwarded: for=192.0.2.43, for=198.51.100.17;proto=https
/// ```
///
/// We only care about `for=`; `by=`, `proto=`, `host=` are ignored.
/// Per RFC 7239 §6: the value is a `token` or `quoted-string`; IPv6
/// MUST be bracketed `[...]`. Port suffix (`:port`) is optional and
/// stripped.
pub fn parse_forwarded(value: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    // Each element separated by `,`. Within an element, `;` separates
    // parameters. We need ONLY the `for=` parameter of each element.
    // RFC 7239 §4 forbids a parameter name appearing more than once
    // per element, so the inner `break` on the first `for=` is
    // protocol-correct (and audit-hardened against repeated-for floods).
    // Outer `.take(MAX_CHAIN_HOPS)` bounds worst-case parsing under
    // adversarial header length.
    for element in value.split(',').take(MAX_CHAIN_HOPS) {
        for pair in element.split(';') {
            let pair = pair.trim();
            // Case-insensitive `for=` prefix per RFC 7239 §4 ("the
            // names defined are case-insensitive").
            let val = match pair.split_once('=') {
                Some((name, v)) if name.trim().eq_ignore_ascii_case("for") => v.trim(),
                _ => continue,
            };
            // Strip surrounding quotes if any (`"..."`).
            let unquoted = val.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(val);
            if let Some(ip) = extract_ip_from_forwarded_for_value(unquoted) {
                out.push(ip);
            }
            // `for` was found in this element; stop scanning further
            // parameters of this element.
            break;
        }
    }
    out
}

/// Extract an `IpAddr` from a `Forwarded for=` value, handling the
/// bracketed-IPv6 + optional port forms. Returns `None` for
/// non-IP values like `_obfuscated` (RFC 7239 obfuscated identifier)
/// or `unknown`.
fn extract_ip_from_forwarded_for_value(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Bracketed IPv6: `[2001:db8::1]` or `[2001:db8::1]:port`.
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        return rest[..end].parse().ok();
    }
    // Plain IPv4 or IPv4:port. IPv6 without brackets isn't valid per
    // RFC 7239 (the colons clash with port syntax), so we only need
    // to handle "ipv4" and "ipv4:port" here.
    if let Some((host, _port)) = s.rsplit_once(':') {
        // If `host` itself contains `:`, this was probably IPv6
        // without brackets — try the whole string as a last resort.
        if host.contains(':') {
            return s.parse().ok();
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    s.parse().ok()
}

/// Resolve the real client IP for an incoming request.
///
/// `peer` is the TCP peer's socket address (from axum
/// `ConnectInfo`). `forwarded_value` is the value of the
/// `Forwarded` header if present; `xff_value` is the
/// `X-Forwarded-For` header if present. `trusted_proxies` lists the
/// operator-configured trust set; loopback is always also trusted.
///
/// Algorithm:
///   1. If the peer is neither loopback nor in `trusted_proxies`,
///      ignore both headers and return the peer.
///   2. Otherwise, build the forwarding chain (prefer `Forwarded`
///      over XFF; concatenation never makes sense), and walk it
///      RIGHT-to-LEFT, skipping addresses that are themselves
///      trusted. Return the first untrusted address encountered.
///   3. If the entire chain is trusted (or empty), return the peer
///      IP — that's the last unspoofable hop we know about.
pub fn resolve_client_ip(
    peer: std::net::SocketAddr,
    forwarded_value: Option<&str>,
    xff_value: Option<&str>,
    trusted_proxies: &TrustedProxies,
) -> IpAddr {
    let peer_ip = peer.ip();
    let peer_trusted = is_loopback_canonical(peer_ip) || trusted_proxies.contains(peer_ip);
    if !peer_trusted {
        return peer_ip;
    }
    // Build the chain. Prefer Forwarded (more precise) when present
    // AND it produced at least one parseable IP; fall back to XFF.
    // Some misconfigured upstreams send both — using Forwarded when
    // it has any value at all matches what nginx / Apache do.
    let chain: Vec<IpAddr> = match forwarded_value {
        Some(v) => {
            let parsed = parse_forwarded(v);
            if parsed.is_empty() {
                xff_value.map(parse_xff).unwrap_or_default()
            } else {
                parsed
            }
        }
        None => xff_value.map(parse_xff).unwrap_or_default(),
    };
    // Right-to-left walk. The first untrusted hop is the real client.
    for candidate in chain.into_iter().rev() {
        if is_loopback_canonical(candidate) || trusted_proxies.contains(candidate) {
            continue;
        }
        return candidate;
    }
    // Entire chain was trusted (or empty). Best we can say is "the
    // request arrived from `peer_ip` — every hop we know about is
    // trusted". Returning the peer is safe and matches the
    // "no forwarding info" base case.
    peer_ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn empty() -> TrustedProxies {
        TrustedProxies::default()
    }

    fn proxies(items: &[&str]) -> TrustedProxies {
        TrustedProxies::from_strings(&items.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap()
    }

    // --- TrustedProxy::parse + matches ---------------------------------

    #[test]
    fn parses_bare_ipv4() {
        let p = TrustedProxy::parse("10.20.30.40").unwrap();
        assert!(p.matches("10.20.30.40".parse().unwrap()));
        assert!(!p.matches("10.20.30.41".parse().unwrap()));
    }

    #[test]
    fn parses_ipv4_cidr() {
        let p = TrustedProxy::parse("10.0.0.0/8").unwrap();
        assert!(p.matches("10.0.0.1".parse().unwrap()));
        assert!(p.matches("10.255.255.255".parse().unwrap()));
        assert!(!p.matches("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parses_ipv6_cidr() {
        let p = TrustedProxy::parse("2001:db8::/32").unwrap();
        assert!(p.matches("2001:db8::1".parse().unwrap()));
        assert!(p.matches("2001:db8:ffff::1".parse().unwrap()));
        assert!(!p.matches("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn parses_ipv6_host_address() {
        let p = TrustedProxy::parse("::1").unwrap();
        assert!(p.matches("::1".parse().unwrap()));
        assert!(!p.matches("::2".parse().unwrap()));
    }

    #[test]
    fn rejects_invalid_prefix() {
        // /33 on IPv4 is impossible.
        assert!(TrustedProxy::parse("1.2.3.4/33").is_err());
        // /129 on IPv6 is impossible.
        assert!(TrustedProxy::parse("2001:db8::/129").is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(TrustedProxy::parse("").is_err());
        assert!(TrustedProxy::parse("not-an-ip").is_err());
        assert!(TrustedProxy::parse("1.2.3.4/abc").is_err());
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_ipv4_cidr() {
        // A trust entry of `127.0.0.0/8` should cover the dual-stack
        // form `::ffff:127.0.0.1` after canonicalization.
        let p = TrustedProxy::parse("127.0.0.0/8").unwrap();
        assert!(p.matches("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn prefix_zero_matches_everything() {
        // `0.0.0.0/0` is the "match anything IPv4" entry. Operator
        // who uses this is explicitly opting in to "trust the world",
        // and the parser shouldn't second-guess them.
        let p4 = TrustedProxy::parse("0.0.0.0/0").unwrap();
        assert!(p4.matches("1.2.3.4".parse().unwrap()));
        assert!(p4.matches("255.255.255.255".parse().unwrap()));
        let p6 = TrustedProxy::parse("::/0").unwrap();
        assert!(p6.matches("2001:db8::1".parse().unwrap()));
    }

    // --- parse_xff ------------------------------------------------------

    #[test]
    fn xff_single_entry() {
        let r = parse_xff("1.2.3.4");
        assert_eq!(r, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn xff_multi_hop_preserves_order() {
        let r = parse_xff("1.2.3.4, 5.6.7.8, 9.10.11.12");
        assert_eq!(
            r,
            vec![
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "5.6.7.8".parse::<IpAddr>().unwrap(),
                "9.10.11.12".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn xff_skips_malformed_entries() {
        let r = parse_xff("not-an-ip, 1.2.3.4, also-garbage, 5.6.7.8");
        assert_eq!(
            r,
            vec![
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "5.6.7.8".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn xff_caps_chain_at_max_hops() {
        // Audit hardening: a 10,000-entry XFF must not cost O(n).
        // Build a 10k chain and assert we stop parsing after
        // MAX_CHAIN_HOPS entries (verified via output length).
        let huge = (0..10_000)
            .map(|_| "1.2.3.4")
            .collect::<Vec<_>>()
            .join(",");
        let r = parse_xff(&huge);
        assert_eq!(r.len(), super::MAX_CHAIN_HOPS, "must cap at MAX_CHAIN_HOPS");
    }

    #[test]
    fn forwarded_caps_chain_at_max_hops() {
        let huge = (0..10_000)
            .map(|_| "for=1.2.3.4")
            .collect::<Vec<_>>()
            .join(",");
        let r = parse_forwarded(&huge);
        assert_eq!(r.len(), super::MAX_CHAIN_HOPS, "must cap at MAX_CHAIN_HOPS");
    }

    #[test]
    fn xff_handles_ipv6_unbracketed() {
        // XFF doesn't bracket IPv6 (unlike Forwarded).
        let r = parse_xff("2001:db8::1, 5.6.7.8");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0], "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    // --- parse_forwarded (RFC 7239) ------------------------------------

    #[test]
    fn forwarded_single_for() {
        let r = parse_forwarded("for=192.0.2.43");
        assert_eq!(r, vec!["192.0.2.43".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn forwarded_quoted_bracketed_ipv6() {
        let r = parse_forwarded(r#"for="[2001:db8:cafe::17]:4711""#);
        assert_eq!(r, vec!["2001:db8:cafe::17".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn forwarded_multi_element() {
        let r = parse_forwarded("for=192.0.2.43, for=198.51.100.17");
        assert_eq!(
            r,
            vec![
                "192.0.2.43".parse::<IpAddr>().unwrap(),
                "198.51.100.17".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn forwarded_extra_directives_ignored() {
        let r = parse_forwarded("for=192.0.2.43;proto=https;by=10.0.0.1");
        assert_eq!(r, vec!["192.0.2.43".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn forwarded_case_insensitive_name() {
        let r = parse_forwarded("FOR=192.0.2.43");
        assert_eq!(r, vec!["192.0.2.43".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn forwarded_skips_obfuscated_identifiers() {
        // RFC 7239 §6 allows "obfuscated" identifiers like `_abc123`
        // and the literal `unknown`. Neither parses as an IP; both
        // are silently skipped.
        let r = parse_forwarded("for=_abc123, for=192.0.2.43, for=unknown");
        assert_eq!(r, vec!["192.0.2.43".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn forwarded_with_port_strips_port() {
        let r = parse_forwarded("for=192.0.2.43:1234");
        assert_eq!(r, vec!["192.0.2.43".parse::<IpAddr>().unwrap()]);
    }

    // --- resolve_client_ip ----------------------------------------------

    #[test]
    fn untrusted_peer_returns_peer_ignoring_headers() {
        // CRITICAL SECURITY: peer not in trust set means we MUST
        // ignore X-Forwarded-For — otherwise any client can claim
        // any IP. Foundation of the v0.41 security boundary.
        let trusted = empty();
        let peer = sock("8.8.8.8:5555");
        let resolved = resolve_client_ip(peer, None, Some("1.2.3.4"), &trusted);
        assert_eq!(resolved, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn loopback_peer_is_implicitly_trusted() {
        // Default trust set is empty; loopback is still trusted.
        let trusted = empty();
        let peer = sock("127.0.0.1:5555");
        let resolved = resolve_client_ip(peer, None, Some("1.2.3.4"), &trusted);
        assert_eq!(resolved, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ipv6_loopback_peer_is_trusted() {
        let trusted = empty();
        let peer = sock("[::1]:5555");
        let resolved = resolve_client_ip(peer, None, Some("1.2.3.4"), &trusted);
        assert_eq!(resolved, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ipv4_mapped_ipv6_loopback_is_trusted() {
        // Dual-stack listener delivers loopback as `::ffff:127.0.0.1`.
        let trusted = empty();
        let peer = sock("[::ffff:127.0.0.1]:5555");
        let resolved = resolve_client_ip(peer, None, Some("1.2.3.4"), &trusted);
        assert_eq!(resolved, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn configured_trusted_proxy_is_trusted() {
        let trusted = proxies(&["10.0.0.0/8"]);
        let peer = sock("10.1.2.3:5555");
        let resolved = resolve_client_ip(peer, None, Some("1.2.3.4"), &trusted);
        assert_eq!(resolved, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rightmost_walk_returns_first_untrusted() {
        // Chain: 1.2.3.4 (real client), 5.6.7.8 (untrusted middle),
        // 10.0.0.1 (trusted proxy). Peer = loopback. Walking right-
        // to-left: 10.0.0.1 trusted → skip; 5.6.7.8 untrusted → STOP.
        // The walk DOES NOT continue past 5.6.7.8 to 1.2.3.4 because
        // 5.6.7.8 might have FAKED the 1.2.3.4 entry.
        let trusted = proxies(&["10.0.0.0/8"]);
        let peer = sock("127.0.0.1:5555");
        let xff = "1.2.3.4, 5.6.7.8, 10.0.0.1";
        let resolved = resolve_client_ip(peer, None, Some(xff), &trusted);
        assert_eq!(resolved, "5.6.7.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rightmost_walk_with_all_trusted_returns_peer() {
        // Every hop in the chain is in the trust set. The walk
        // exhausts the chain without finding an untrusted address.
        // Best answer is the peer itself.
        let trusted = proxies(&["10.0.0.0/8"]);
        let peer = sock("127.0.0.1:5555");
        let xff = "10.0.0.5, 10.0.0.1";
        let resolved = resolve_client_ip(peer, None, Some(xff), &trusted);
        assert_eq!(resolved, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rightmost_walk_full_trust_chain_returns_original_client() {
        // CDN setup: client 1.2.3.4 → CDN edge 5.6.7.8 → Apache
        // (loopback peer). Both CDN edge AND loopback are trusted.
        // Walk: 5.6.7.8 trusted → skip; 1.2.3.4 untrusted → return.
        let trusted = proxies(&["5.6.7.0/24"]);
        let peer = sock("127.0.0.1:5555");
        let xff = "1.2.3.4, 5.6.7.8";
        let resolved = resolve_client_ip(peer, None, Some(xff), &trusted);
        assert_eq!(resolved, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn forwarded_header_preferred_over_xff() {
        // Both headers present. Forwarded wins.
        let trusted = empty();
        let peer = sock("127.0.0.1:5555");
        let resolved = resolve_client_ip(
            peer,
            Some("for=4.4.4.4"),
            Some("9.9.9.9"),
            &trusted,
        );
        assert_eq!(resolved, "4.4.4.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn forwarded_with_no_for_falls_back_to_xff() {
        // `Forwarded` header is present but has no `for=` directive
        // (just `proto=https`). XFF should still be consulted.
        let trusted = empty();
        let peer = sock("127.0.0.1:5555");
        let resolved = resolve_client_ip(
            peer,
            Some("proto=https"),
            Some("9.9.9.9"),
            &trusted,
        );
        assert_eq!(resolved, "9.9.9.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn no_headers_returns_peer() {
        let trusted = empty();
        let peer = sock("127.0.0.1:5555");
        let resolved = resolve_client_ip(peer, None, None, &trusted);
        assert_eq!(resolved, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn forwarded_bracketed_ipv6_with_trusted_chain() {
        // RFC 7239: IPv6 must be bracketed. Verify the bracketed
        // form works alongside the rightmost-walk semantics.
        let trusted = proxies(&["2001:db8::/32"]);
        let peer = sock("[::1]:5555");
        let resolved = resolve_client_ip(
            peer,
            Some(r#"for="[2001:cafe::1]", for="[2001:db8::1]""#),
            None,
            &trusted,
        );
        assert_eq!(
            resolved,
            "2001:cafe::1".parse::<IpAddr>().unwrap(),
            "rightmost-walk skips 2001:db8::1 (trusted), returns 2001:cafe::1",
        );
    }
}
