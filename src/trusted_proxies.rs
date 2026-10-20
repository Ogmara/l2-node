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
//! - **RFC 7239 `Forwarded`** (`for=` of each element) and
//!   **`X-Forwarded-For`** (comma-separated). Each is walked on its own;
//!   if both yield a chain and the answers differ the result is `::`
//!   (l2-node 0.140.0 — a proxy maintains one header and passes the other
//!   through from the client, so neither may simply win). Only the LAST
//!   `MAX_CHAIN_HOPS` entries of a header are read, and every field line
//!   of a repeated header counts.
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
///
/// **The cap keeps the TAIL (rightmost entries), never the head**
/// (l2-node 0.140.0 security fix). The rightmost entries are the ones
/// our own proxies appended; the leftmost are whatever the client sent.
/// Keeping the head let a client pad the header with more than 32
/// spoofed entries so the proxy-appended real address was cut off and
/// the resolver returned an address of the client's choosing (or, with
/// padding made of trusted/loopback entries, the loopback peer itself).
pub(crate) const MAX_CHAIN_HOPS: usize = 32;

/// The last `MAX_CHAIN_HOPS` comma-separated segments of `value`, in
/// chain order (left to right). `rsplit` walks from the right, so the
/// work is bounded by the kept segments, not the header length.
fn tail_segments(value: &str) -> Vec<&str> {
    let mut tail: Vec<&str> = value.rsplit(',').take(MAX_CHAIN_HOPS).collect();
    tail.reverse();
    tail
}

/// True when `value` has more than `MAX_CHAIN_HOPS` comma-separated
/// segments, i.e. the parsers below dropped its leftmost part.
fn chain_truncated(value: &str) -> bool {
    value.split(',').nth(MAX_CHAIN_HOPS).is_some()
}

/// One hop of a parsed forwarding chain: the address, or `None` for an
/// entry that is not one (garbage, `unknown`, an RFC 7239 obfuscated
/// identifier, an empty segment).
///
/// Unparseable entries are KEPT in position (l2-node 0.140.0 security
/// fix) rather than dropped: the right-to-left walk stops at the first
/// one and fails closed (see `walk_chain`). Dropping them let the walk
/// step over an entry the node could not interpret and return an address
/// further left — which is client-controlled territory.
pub type Hop = Option<IpAddr>;

/// Parse an `X-Forwarded-For` header value into an ordered list of
/// hops (leftmost = original client, rightmost = closest hop). Each
/// entry is a bare IPv4/IPv6 address, or one with a port (`1.2.3.4:5678`,
/// `[2001:db8::1]:5678` — Azure Application Gateway and some load
/// balancers append the client port). Any other entry is kept as `None`
/// (see `Hop`).
///
/// Only the LAST `MAX_CHAIN_HOPS` entries are parsed (the
/// proxy-appended end); anything to their left is dropped to bound
/// worst-case work under adversarial-length headers.
pub fn parse_xff(value: &str) -> Vec<Hop> {
    tail_segments(value)
        .into_iter()
        .map(extract_ip_from_forwarded_for_value)
        .collect()
}

/// Parse an RFC 7239 `Forwarded` header value into an ordered list
/// of hops from the `for=` parameter of each element. Same ordering
/// convention as `parse_xff`: leftmost = original client. An element
/// whose `for=` value is not an address (`unknown`, `_obfuscated`), or
/// that has no `for=` at all while other elements do, is a `None` hop.
/// A header with no `for=` anywhere (e.g. only `proto=https`) yields an
/// empty chain, i.e. it is treated as absent.
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
pub fn parse_forwarded(value: &str) -> Vec<Hop> {
    let mut out = Vec::new();
    let mut any_for = false;
    // Each element separated by `,`. Within an element, `;` separates
    // parameters. We need ONLY the `for=` parameter of each element.
    // RFC 7239 §4 forbids a parameter name appearing more than once
    // per element, so the inner `break` on the first `for=` is
    // protocol-correct (and audit-hardened against repeated-for floods).
    // Only the LAST `MAX_CHAIN_HOPS` elements (the proxy-appended end) are
    // parsed — bounds worst-case parsing under adversarial header length
    // without letting a client push the real hops out (see
    // `MAX_CHAIN_HOPS`).
    for element in tail_segments(value) {
        let mut hop: Hop = None;
        for pair in element.split(';') {
            let pair = pair.trim();
            // Case-insensitive `for=` prefix per RFC 7239 §4 ("the
            // names defined are case-insensitive").
            let val = match pair.split_once('=') {
                Some((name, v)) if name.trim().eq_ignore_ascii_case("for") => v.trim(),
                _ => continue,
            };
            any_for = true;
            // Strip surrounding quotes if any (`"..."`).
            let unquoted = val.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(val);
            hop = extract_ip_from_forwarded_for_value(unquoted);
            // `for` was found in this element; stop scanning further
            // parameters of this element.
            break;
        }
        out.push(hop);
    }
    if !any_for {
        // No `for=` anywhere: this header carries no chain (a proxy that
        // only records `proto=`/`host=`); let `X-Forwarded-For` decide.
        out.clear();
    }
    out
}

/// Extract an `IpAddr` from a `Forwarded for=` value or an
/// `X-Forwarded-For` entry, handling the bracketed-IPv6 + optional port
/// forms. Returns `None` for non-IP values like `_obfuscated` (RFC 7239
/// obfuscated identifier) or `unknown`.
fn extract_ip_from_forwarded_for_value(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Bracketed IPv6: `[2001:db8::1]` or `[2001:db8::1]:port`.
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        // Only `[addr]` or `[addr]:port` — anything else after the bracket
        // is not an address form we recognise.
        let after = &rest[end + 1..];
        if !(after.is_empty() || is_port_suffix(after)) {
            return None;
        }
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
            if !is_port_suffix(&s[host.len()..]) {
                return None;
            }
            return Some(ip);
        }
    }
    s.parse().ok()
}

/// True for `:` followed by 1-5 ASCII digits that fit a `u16`.
fn is_port_suffix(s: &str) -> bool {
    s.strip_prefix(':')
        .filter(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|p| p.parse::<u16>().ok())
        .is_some()
}

/// Resolve the real client IP for an incoming request.
///
/// `peer` is the TCP peer's socket address (from axum
/// `ConnectInfo`). `forwarded_value` is the value of the
/// `Forwarded` header if present; `xff_value` is the
/// `X-Forwarded-For` header if present. `trusted_proxies` lists the
/// operator-configured trust set; loopback is always also trusted.
///
/// Algorithm (standard right-to-left resolution):
///   1. If the peer is neither loopback nor in `trusted_proxies`,
///      ignore both headers and return the peer.
///   2. Otherwise, build each header's forwarding chain from its LAST
///      `MAX_CHAIN_HOPS` entries and walk it RIGHT-to-LEFT, skipping
///      addresses that are themselves trusted; the first untrusted
///      address is the client. If BOTH `Forwarded` and `X-Forwarded-For`
///      yield a chain and the two answers differ, return `::` (see the
///      body for why neither header may simply win).
///   3. If every kept entry is trusted but the header was longer than
///      `MAX_CHAIN_HOPS`, the client lies beyond what we parsed: return
///      the unspecified address `::` (never loopback, never a value
///      the client chose) rather than the peer.
///   4. If the walk reaches an entry that is not an address (garbage,
///      `unknown`, an obfuscated identifier) before finding an untrusted
///      one, return `::` — the hops to its left cannot be trusted
///      (l2-node 0.140.0; previously such entries were skipped).
///   5. If the entire chain is trusted (or empty), return the peer
///      IP — that's the last unspoofable hop we know about. NOTE: for a
///      loopback peer this is loopback; callers that grant a privilege
///      to loopback must not use this alone — see
///      `direct_loopback_request`.
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
    // Resolve each header's chain on its own. A reverse proxy normally
    // maintains ONE of the two headers and passes the other through from
    // the client verbatim, and the node cannot know which: preferring
    // either one unconditionally lets a client choose its address by
    // sending the other (before 0.140.0 a client-sent `Forwarded` beat the
    // `X-Forwarded-For` an Apache/nginx proxy appended to). When both carry
    // a chain and they DISAGREE, fail closed to `::` (shared, never
    // loopback, never client-chosen); when they agree (a proxy maintaining
    // both), or only one is present, use it.
    let fwd = forwarded_value
        .map(|v| (parse_forwarded(v), chain_truncated(v)))
        .filter(|(chain, _)| !chain.is_empty());
    let xff = xff_value
        .map(|v| (parse_xff(v), chain_truncated(v)))
        .filter(|(chain, _)| !chain.is_empty());
    match (fwd, xff) {
        (Some((f, ft)), Some((x, xt))) => {
            let a = walk_chain(peer_ip, f, ft, trusted_proxies);
            let b = walk_chain(peer_ip, x, xt, trusted_proxies);
            if a == b {
                a
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            }
        }
        (Some((chain, truncated)), None) | (None, Some((chain, truncated))) => {
            walk_chain(peer_ip, chain, truncated, trusted_proxies)
        }
        (None, None) => peer_ip,
    }
}

/// Right-to-left walk over one parsed chain (steps 2-5 of
/// `resolve_client_ip`).
fn walk_chain(
    peer_ip: IpAddr,
    chain: Vec<Hop>,
    truncated: bool,
    trusted_proxies: &TrustedProxies,
) -> IpAddr {
    // The first untrusted hop is the real client.
    for hop in chain.into_iter().rev() {
        let candidate = match hop {
            Some(ip) => ip,
            // An entry we cannot interpret ends the walk (l2-node 0.140.0):
            // everything to its left is unverifiable, so stepping over it
            // would let the client pick the answer. Fail closed to the
            // shared, never-loopback, never-client-chosen `::`.
            None => return IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        if is_loopback_canonical(candidate) || trusted_proxies.contains(candidate) {
            continue;
        }
        return candidate;
    }
    if truncated {
        // 32+ trusted hops and more beyond: unresolvable. Fail closed to
        // a shared, non-loopback, non-client-chosen address.
        return IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    }
    // Entire chain was trusted. Best we can say is "the request arrived
    // from `peer_ip` — every hop we know about is trusted".
    peer_ip
}

/// All values of header `name`, joined in order with `,` — the
/// RFC 9110 §5.3 combination of repeated field lines. `None` if absent.
/// Bytes that are not valid UTF-8 become U+FFFD instead of discarding
/// the whole header, so a client cannot hide the proxy-appended entry by
/// prefixing a non-ASCII byte. Using only the FIRST field line (as
/// `HeaderMap::get` does) let a client's own `X-Forwarded-For` line
/// shadow the one a proxy added as a separate line.
pub fn joined_header_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter().peekable();
    values.peek()?;
    Some(
        values
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect::<Vec<_>>()
            .join(","),
    )
}

/// `resolve_client_ip` over a request's headers (`Forwarded`, then
/// `X-Forwarded-For`, every field line of each — see
/// `joined_header_value`). The single entry point for every IP-keyed
/// decision (rate limiter key, per-IP federation slots, admin auth).
pub fn resolve_client_ip_from_headers(
    peer: std::net::SocketAddr,
    headers: &axum::http::HeaderMap,
    trusted_proxies: &TrustedProxies,
) -> IpAddr {
    let forwarded = joined_header_value(headers, "forwarded");
    let xff = joined_header_value(headers, "x-forwarded-for");
    resolve_client_ip(peer, forwarded.as_deref(), xff.as_deref(), trusted_proxies)
}

/// Headers whose presence means the request came through a proxy (or
/// claims to). Any one of them disqualifies the loopback admin bypass.
pub const PROXY_HEADERS: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-server",
    "x-real-ip",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "via",
];

/// The admin dashboard's localhost bypass (spec 10 §5.6): true ONLY for a
/// request that is a local, non-browser-cross-origin call to the node's own
/// port. ALL of the following must hold:
///
/// 1. **TCP peer is loopback** (`127.0.0.0/8`, `::1`, `::ffff:127.x`).
/// 2. **No proxy header at all** (`PROXY_HEADERS`). A request that came
///    through a reverse proxy is never "localhost", even when the proxy is
///    on loopback and every forwarded hop is loopback/trusted: the resolver
///    then falls back to the (loopback) peer, and that fallback is not
///    proof of a local client. Before 0.140.0 the bypass used the resolved
///    IP, so a padded header (head-truncation, see `MAX_CHAIN_HOPS`), a
///    proxy that adds its own header line instead of appending, or a header
///    made unparseable could make a remote request through a loopback proxy
///    resolve to loopback.
/// 3. **The request's own host is a loopback literal or `localhost`**
///    (`Host`, or the HTTP/2 `:authority` when `Host` is absent): one of
///    `127.x.y.z`, `[::1]` (or another bracketed loopback IPv6 form),
///    `localhost` (ASCII case-insensitive), each with an optional `:port`.
///    Absent, repeated, non-UTF-8 or any other host denies. This defeats
///    DNS rebinding: a hostile page whose name was re-pointed at 127.0.0.1
///    still sends its OWN name as `Host`.
/// 4. **`Origin` absent, or same-origin with that host** (`http`/`https`
///    scheme; host and effective port equal to the request's host, the
///    scheme's default port filling a missing one). `Origin: null`, a
///    repeated or unparseable `Origin`, or any other origin denies. This
///    stops a page the operator opens in a browser on the node host from
///    driving the admin API (governance votes, claims, peer bans) through
///    `fetch('http://127.0.0.1:<port>/admin/...')` — the TCP peer is
///    loopback for that request too.
/// 5. **`Sec-Fetch-Site` absent, `none` or `same-origin`** (see
///    `sec_fetch_site_allows_admin`).
///
/// curl/scripts on the host (no `Origin`, `Host: 127.0.0.1:<port>`) and the
/// built-in dashboard opened at `http://127.0.0.1:<port>/admin/dashboard`
/// or `http://localhost:<port>/...` (same-origin `Origin`, including the
/// dashboard websocket) keep working. Local operators behind a proxy, or who
/// open the dashboard under any other name, authenticate with
/// `[api.admin] admin_wallets`. The whole bypass can be switched off with
/// `[api.admin] localhost_bypass = false` (checked by the caller,
/// `admin_auth_middleware`).
pub fn direct_loopback_request(
    peer: std::net::SocketAddr,
    headers: &axum::http::HeaderMap,
    uri_authority: Option<&str>,
) -> bool {
    if !is_loopback_canonical(peer.ip()) || PROXY_HEADERS.iter().any(|h| headers.contains_key(*h)) {
        return false;
    }
    // (3) The request's own host.
    let host = match single_header(headers, "host") {
        Ok(Some(h)) => h,
        Ok(None) => match uri_authority {
            Some(a) => a,
            None => return false,
        },
        Err(()) => return false,
    };
    let Some(own) = parse_loopback_authority(host) else {
        return false;
    };
    // (4) Origin: absent or same-origin.
    match single_header(headers, "origin") {
        Ok(None) => {}
        Ok(Some(origin)) => {
            let Some((scheme_port, authority)) = split_origin(origin) else {
                return false;
            };
            let Some(theirs) = parse_loopback_authority(authority) else {
                return false;
            };
            if own.host != theirs.host
                || own.port.unwrap_or(scheme_port) != theirs.port.unwrap_or(scheme_port)
            {
                return false;
            }
        }
        Err(()) => return false,
    }
    // (5) Fetch metadata.
    sec_fetch_site_allows_admin(headers)
}

/// `Sec-Fetch-Site` gate applied to EVERY protected admin request (the
/// localhost bypass and the session-token path alike): a browser that sends
/// it says whether the request was initiated by the same origin. Only
/// `same-origin` (the dashboard's own calls) and `none` (the operator typed
/// the URL / opened a bookmark) are accepted; `same-site` and `cross-site`
/// are refused. Absent = a non-browser client or an old browser: allowed
/// here (the other checks still apply). A repeated or non-UTF-8 value is
/// refused. Unlike an `Origin`-vs-`Host` comparison this does not depend on
/// how a reverse proxy rewrites `Host`, so it is safe on the proxied path.
pub fn sec_fetch_site_allows_admin(headers: &axum::http::HeaderMap) -> bool {
    match single_header(headers, "sec-fetch-site") {
        Ok(None) => true,
        Ok(Some(v)) => {
            let v = v.trim();
            v.eq_ignore_ascii_case("same-origin") || v.eq_ignore_ascii_case("none")
        }
        Err(()) => false,
    }
}

/// The single value of header `name`: `Ok(None)` if absent, `Err(())` if
/// it is repeated or not valid UTF-8 (both refused by the admin checks —
/// there is no unambiguous reading).
fn single_header<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut it = headers.get_all(name).iter();
    let Some(first) = it.next() else {
        return Ok(None);
    };
    if it.next().is_some() {
        return Err(());
    }
    first.to_str().map(Some).map_err(|_| ())
}

/// A loopback host as seen in `Host` / `Origin`.
#[derive(Debug, PartialEq, Eq)]
struct LoopbackAuthority {
    /// `Localhost` or the parsed loopback address (so `[::1]` and
    /// `[0:0:0:0:0:0:0:1]` compare equal).
    host: LoopbackHost,
    port: Option<u16>,
}

#[derive(Debug, PartialEq, Eq)]
enum LoopbackHost {
    Localhost,
    Ip(IpAddr),
}

/// Parse `host[:port]` and accept it only if the host is a loopback IP
/// literal (`127.x.y.z`, bracketed loopback IPv6) or `localhost` (ASCII
/// case-insensitive, no trailing dot). Anything else — a DNS name, a
/// non-loopback IP, userinfo, a path, an empty or out-of-range port — is
/// `None`.
fn parse_loopback_authority(s: &str) -> Option<LoopbackAuthority> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let ip: Ipv6Addr = rest[..end].parse().ok()?;
        let after = &rest[end + 1..];
        let port = if after.is_empty() {
            None
        } else if is_port_suffix(after) {
            Some(after[1..].parse::<u16>().ok()?)
        } else {
            return None;
        };
        (LoopbackHost::Ip(IpAddr::V6(ip)), port)
    } else {
        let (h, port) = match s.split_once(':') {
            Some((h, p)) => {
                if !is_port_suffix(&s[h.len()..]) {
                    return None;
                }
                (h, Some(p.parse::<u16>().ok()?))
            }
            None => (s, None),
        };
        if h.eq_ignore_ascii_case("localhost") {
            (LoopbackHost::Localhost, port)
        } else {
            (LoopbackHost::Ip(IpAddr::V4(h.parse::<Ipv4Addr>().ok()?)), port)
        }
    };
    if let LoopbackHost::Ip(ip) = host {
        if !is_loopback_canonical(ip) {
            return None;
        }
    }
    Some(LoopbackAuthority { host, port })
}

/// Split a serialized origin `scheme://authority` into (the scheme's
/// default port, authority). Only `http` and `https` are accepted; an
/// origin never carries a path, query, fragment or userinfo, so any of
/// those (and `null`) is `None`.
fn split_origin(origin: &str) -> Option<(u16, &str)> {
    let (scheme, rest) = origin.split_once("://")?;
    let default_port = if scheme.eq_ignore_ascii_case("http") {
        80
    } else if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        return None;
    };
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return None;
    }
    Some((default_port, rest))
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

    /// `Some(ip)` hops from address literals.
    fn hops(v: &[&str]) -> Vec<Hop> {
        v.iter().map(|s| Some(s.parse::<IpAddr>().unwrap())).collect()
    }

    #[test]
    fn xff_single_entry() {
        assert_eq!(parse_xff("1.2.3.4"), hops(&["1.2.3.4"]));
    }

    #[test]
    fn xff_multi_hop_preserves_order() {
        let r = parse_xff("1.2.3.4, 5.6.7.8, 9.10.11.12");
        assert_eq!(r, hops(&["1.2.3.4", "5.6.7.8", "9.10.11.12"]));
    }

    /// 0.140.0 (round-5 S-N1): malformed entries are KEPT as `None` in
    /// position (the walk fails closed on them), no longer skipped.
    #[test]
    fn xff_keeps_malformed_entries_in_position() {
        let r = parse_xff("not-an-ip, 1.2.3.4, also-garbage, 5.6.7.8");
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        assert_eq!(r, vec![None, ip("1.2.3.4"), None, ip("5.6.7.8")]);
        // Empty segments, `unknown`, obfuscated ids and bad ports too.
        for bad in ["", " ", "unknown", "_hidden", "1.2.3.4:", "1.2.3.4:99999", "1.2.3.4:x", "[::1]x", "[::1"] {
            assert_eq!(parse_xff(bad), vec![None], "{bad:?}");
        }
    }

    /// `ip:port` (Azure Application Gateway, some LBs) and `[v6]:port` are
    /// addresses, not garbage.
    #[test]
    fn xff_accepts_ip_with_port() {
        assert_eq!(parse_xff("203.0.113.9:51234"), hops(&["203.0.113.9"]));
        assert_eq!(parse_xff("[2001:db8::7]:443, [2001:db8::8]"), hops(&["2001:db8::7", "2001:db8::8"]));
    }

    #[test]
    fn xff_cap_keeps_the_tail_not_the_head() {
        // 0.140.0 security fix: the kept window is the RIGHTMOST (proxy-
        // appended) end of the chain.
        let chain = (0..100).map(|i| format!("10.0.0.{i}")).collect::<Vec<_>>().join(", ");
        let r = parse_xff(&chain);
        assert_eq!(r.len(), super::MAX_CHAIN_HOPS);
        assert_eq!(r.last(), Some(&Some("10.0.0.99".parse::<IpAddr>().unwrap())));
        assert_eq!(r[0], Some("10.0.0.68".parse::<IpAddr>().unwrap()));
        let fwd = (0..100).map(|i| format!("for=10.0.1.{i}")).collect::<Vec<_>>().join(", ");
        let r = parse_forwarded(&fwd);
        assert_eq!(r.len(), super::MAX_CHAIN_HOPS);
        assert_eq!(r.last(), Some(&Some("10.0.1.99".parse::<IpAddr>().unwrap())));
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
        assert_eq!(r, hops(&["2001:db8::1", "5.6.7.8"]));
    }

    // --- parse_forwarded (RFC 7239) ------------------------------------

    #[test]
    fn forwarded_single_for() {
        assert_eq!(parse_forwarded("for=192.0.2.43"), hops(&["192.0.2.43"]));
    }

    #[test]
    fn forwarded_quoted_bracketed_ipv6() {
        let r = parse_forwarded(r#"for="[2001:db8:cafe::17]:4711""#);
        assert_eq!(r, hops(&["2001:db8:cafe::17"]));
    }

    #[test]
    fn forwarded_multi_element() {
        let r = parse_forwarded("for=192.0.2.43, for=198.51.100.17");
        assert_eq!(r, hops(&["192.0.2.43", "198.51.100.17"]));
    }

    #[test]
    fn forwarded_extra_directives_ignored() {
        let r = parse_forwarded("for=192.0.2.43;proto=https;by=10.0.0.1");
        assert_eq!(r, hops(&["192.0.2.43"]));
    }

    #[test]
    fn forwarded_case_insensitive_name() {
        assert_eq!(parse_forwarded("FOR=192.0.2.43"), hops(&["192.0.2.43"]));
    }

    #[test]
    fn forwarded_keeps_obfuscated_identifiers_as_unparseable_hops() {
        // RFC 7239 §6 allows "obfuscated" identifiers like `_abc123`
        // and the literal `unknown`. Neither is an address: both stay in
        // position as `None` (round-5 S-N1 — the walk fails closed there).
        let r = parse_forwarded("for=_abc123, for=192.0.2.43, for=unknown");
        assert_eq!(r, vec![None, Some("192.0.2.43".parse::<IpAddr>().unwrap()), None]);
        // An element without `for=` among ones with it is a `None` hop...
        assert_eq!(parse_forwarded("for=192.0.2.43, proto=https").len(), 2);
        assert_eq!(parse_forwarded("for=192.0.2.43, proto=https")[1], None);
        // ...but a header with no `for=` at all carries no chain.
        assert!(parse_forwarded("proto=https;host=example.org").is_empty());
    }

    #[test]
    fn forwarded_with_port_strips_port() {
        assert_eq!(parse_forwarded("for=192.0.2.43:1234"), hops(&["192.0.2.43"]));
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
    fn disagreeing_forwarded_and_xff_fail_closed() {
        // 0.140.0: neither header may simply win. An Apache/nginx proxy
        // appends to X-Forwarded-For and passes a client-sent `Forwarded`
        // through verbatim — preferring `Forwarded` let the client choose
        // its address. Disagreement → `::`.
        let peer = sock("127.0.0.1:5555");
        let resolved = resolve_client_ip(peer, Some("for=4.4.4.4"), Some("9.9.9.9"), &empty());
        assert_eq!(resolved, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert!(!is_loopback_canonical(resolved));
        // A proxy maintaining both consistently: agreed answer.
        let resolved = resolve_client_ip(peer, Some("for=4.4.4.4"), Some("4.4.4.4"), &empty());
        assert_eq!(resolved, "4.4.4.4".parse::<IpAddr>().unwrap());
        // Only one present: that one.
        assert_eq!(
            resolve_client_ip(peer, Some("for=4.4.4.4"), None, &empty()),
            "4.4.4.4".parse::<IpAddr>().unwrap()
        );
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
    fn spoofed_leftmost_loopback_does_not_bypass_admin_auth() {
        // REGRESSION for admin_auth C1 (audit 2026-06-07): the old admin
        // middleware read the LEFTMOST XFF entry. In the Docker/Apache
        // topology the node's TCP peer is the trusted bridge gateway, so
        // an attacker sends `X-Forwarded-For: 127.0.0.1`; an appending
        // proxy (Apache mod_proxy default) yields `127.0.0.1, <attacker>`.
        // Reading leftmost gave `127.0.0.1` → loopback → auth bypass.
        // The right-to-left walk MUST return the attacker, not loopback.
        let trusted = proxies(&["172.17.0.0/16"]);
        let peer = sock("172.17.0.1:5555"); // Docker bridge gateway (trusted)
        let xff = "127.0.0.1, 8.8.8.8"; // attacker-spoofed loopback, then attacker
        let resolved = resolve_client_ip(peer, None, Some(xff), &trusted);
        assert_eq!(resolved, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert!(
            !is_loopback_canonical(resolved),
            "spoofed leftmost loopback must NOT resolve to a loopback client IP",
        );
    }

    // --- 0.140.0 padding attack ------------------------------------------

    /// The reported attack: a loopback reverse proxy (Apache on the same
    /// host) appends the real client to a header the client padded with 40
    /// loopback entries. Head-keeping parsed only the padding, found every
    /// hop trusted, fell back to the loopback PEER → treated as localhost.
    #[test]
    fn loopback_padding_no_longer_resolves_to_loopback() {
        let pad = vec!["127.0.0.1"; 40].join(", ");
        let xff = format!("{pad}, 203.0.113.9");
        let resolved = resolve_client_ip(sock("127.0.0.1:5555"), None, Some(&xff), &empty());
        assert_eq!(resolved, "203.0.113.9".parse::<IpAddr>().unwrap());
        assert!(!is_loopback_canonical(resolved));
        // Same through RFC 7239 `Forwarded`.
        let fpad = vec!["for=127.0.0.1"; 40].join(", ");
        let fwd = format!("{fpad}, for=203.0.113.9");
        let resolved = resolve_client_ip(sock("127.0.0.1:5555"), Some(&fwd), None, &empty());
        assert_eq!(resolved, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    /// Padding with UNTRUSTED entries of the client's choice used to make
    /// the resolver return the client's chosen address.
    #[test]
    fn padding_cannot_choose_the_resolved_ip() {
        let pad = vec!["198.51.100.66"; 40].join(", ");
        let xff = format!("{pad}, 203.0.113.9");
        let resolved = resolve_client_ip(sock("127.0.0.1:5555"), None, Some(&xff), &empty());
        assert_eq!(resolved, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    /// 32+ TRUSTED hops with more beyond: unresolvable → `::` (shared,
    /// never loopback, never the peer, never client-chosen).
    #[test]
    fn overlong_all_trusted_tail_fails_closed() {
        let trusted = proxies(&["10.0.0.0/8"]);
        let tail = (0..40).map(|i| format!("10.0.0.{i}")).collect::<Vec<_>>().join(", ");
        let xff = format!("203.0.113.9, {tail}");
        let resolved = resolve_client_ip(sock("127.0.0.1:5555"), None, Some(&xff), &trusted);
        assert_eq!(resolved, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert!(!is_loopback_canonical(resolved));
        // Exactly MAX_CHAIN_HOPS trusted entries is not truncated: peer.
        let exact = (0..super::MAX_CHAIN_HOPS).map(|i| format!("10.0.0.{i}")).collect::<Vec<_>>().join(", ");
        assert_eq!(
            resolve_client_ip(sock("127.0.0.1:5555"), None, Some(&exact), &trusted),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn multi_hop_chain_with_trusted_proxies_and_ipv6() {
        // client (IPv6) → CDN 2001:db8::5 (trusted) → LB 10.1.1.1
        // (trusted) → us (peer = LB).
        let trusted = proxies(&["10.0.0.0/8", "2001:db8::/32"]);
        let xff = "2001:cafe::1, 2001:db8::5";
        let resolved = resolve_client_ip(sock("10.1.1.1:443"), None, Some(xff), &trusted);
        assert_eq!(resolved, "2001:cafe::1".parse::<IpAddr>().unwrap());
        // Spoofed leading entries before the real client are ignored.
        let xff = "127.0.0.1, ::1, 2001:cafe::1, 2001:db8::5";
        let resolved = resolve_client_ip(sock("10.1.1.1:443"), None, Some(xff), &trusted);
        assert_eq!(resolved, "2001:cafe::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn spoofed_headers_from_an_untrusted_peer_are_ignored() {
        let pad = vec!["127.0.0.1"; 40].join(", ");
        for peer in ["8.8.8.8:1", "[2001:4860::8888]:1"] {
            let p = sock(peer);
            assert_eq!(resolve_client_ip(p, Some("for=127.0.0.1"), Some(&pad), &empty()), p.ip());
        }
    }

    #[test]
    fn garbage_left_of_the_client_is_irrelevant() {
        // The first untrusted hop is found before the walk reaches the
        // garbage: it is the answer.
        let xff = "not-an-ip, \u{fffd}\u{fffd}, 999.1.1.1, , 203.0.113.9";
        assert_eq!(
            resolve_client_ip(sock("127.0.0.1:1"), None, Some(xff), &empty()),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // All garbage: the walk stops at once → `::` (round-5 S-N1; it used
        // to fall back to the loopback peer).
        assert_eq!(
            resolve_client_ip(sock("127.0.0.1:1"), None, Some("garbage, unknown"), &empty()),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        );
    }

    /// Round-5 S-N1: an entry the walk cannot interpret ENDS it, failing
    /// closed to `::`. Skipping it let the client choose the answer: the
    /// address to the left of an unparseable hop is client territory.
    #[test]
    fn unparseable_hop_ends_the_walk_fail_closed() {
        let unspec = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let trusted = proxies(&["10.0.0.0/8"]);
        // Client-chosen 198.51.100.66, then an entry the trusted proxy wrote
        // in a form we cannot read, then the trusted proxy itself.
        for bad in ["unknown", "_obf", "garbage", "", "1.2.3.4:99999"] {
            let xff = format!("198.51.100.66, {bad}, 10.0.0.5");
            assert_eq!(
                resolve_client_ip(sock("127.0.0.1:1"), None, Some(&xff), &trusted),
                unspec,
                "XFF {xff:?}"
            );
        }
        for bad in ["for=unknown", "for=_obf", "for=\"garbage\"", "proto=https"] {
            let fwd = format!("for=198.51.100.66, {bad}, for=10.0.0.5");
            assert_eq!(
                resolve_client_ip(sock("127.0.0.1:1"), Some(&fwd), None, &trusted),
                unspec,
                "Forwarded {fwd:?}"
            );
        }
        // Never loopback.
        assert!(!is_loopback_canonical(unspec));
        // Common Apache/nginx shapes still resolve.
        assert_eq!(
            resolve_client_ip(sock("127.0.0.1:1"), None, Some("203.0.113.9"), &empty()),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            resolve_client_ip(sock("127.0.0.1:1"), None, Some("198.51.100.1, 203.0.113.9"), &empty()),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // Azure-style ip:port is an address, not garbage.
        assert_eq!(
            resolve_client_ip(sock("127.0.0.1:1"), None, Some("203.0.113.9:50123, 10.0.0.5"), &trusted),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // A Forwarded header that only says `proto=` defers to XFF.
        assert_eq!(
            resolve_client_ip(sock("127.0.0.1:1"), Some("proto=https"), Some("203.0.113.9"), &empty()),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    fn headers(pairs: &[(&'static str, &[u8])]) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, axum::http::HeaderValue::from_bytes(v).unwrap());
        }
        h
    }

    /// A client's own `X-Forwarded-For` line must not shadow the line a
    /// proxy ADDED (HAProxy-style) — every field line is combined in order.
    #[test]
    fn repeated_header_lines_are_combined_in_order() {
        let h = headers(&[("x-forwarded-for", b"127.0.0.1"), ("x-forwarded-for", b"203.0.113.9")]);
        assert_eq!(joined_header_value(&h, "x-forwarded-for").as_deref(), Some("127.0.0.1,203.0.113.9"));
        assert_eq!(
            resolve_client_ip_from_headers(sock("127.0.0.1:1"), &h, &empty()),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    /// A non-UTF-8 byte the client put in front must not discard the
    /// proxy-appended entry (it did with `to_str()`, falling back to the
    /// loopback peer).
    #[test]
    fn non_utf8_prefix_does_not_hide_the_appended_entry() {
        let h = headers(&[("x-forwarded-for", b"\xff\xfe, 203.0.113.9")]);
        assert_eq!(
            resolve_client_ip_from_headers(sock("127.0.0.1:1"), &h, &empty()),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    // --- Admin localhost bypass ------------------------------------------

    /// `direct_loopback_request` with a header list and no URI authority.
    fn bypass(peer: &str, pairs: &[(&'static str, &[u8])]) -> bool {
        direct_loopback_request(sock(peer), &headers(pairs), None)
    }

    #[test]
    fn admin_bypass_only_for_a_direct_loopback_request() {
        let none = headers(&[("host", b"127.0.0.1:41721")]);
        assert!(direct_loopback_request(sock("127.0.0.1:1"), &none, None));
        assert!(direct_loopback_request(sock("[::1]:1"), &none, None));
        assert!(direct_loopback_request(sock("[::ffff:127.0.0.1]:1"), &none, None));
        assert!(!direct_loopback_request(sock("10.0.0.1:1"), &none, None));
        assert!(!direct_loopback_request(sock("8.8.8.8:1"), &none, None));
        // Through a loopback proxy: never the bypass, whatever the header
        // says — including the padding attack and an all-loopback chain.
        let pad = format!("{}, 203.0.113.9", vec!["127.0.0.1"; 40].join(", "));
        for (name, value) in [
            ("x-forwarded-for", pad.as_bytes()),
            ("x-forwarded-for", b"127.0.0.1".as_slice()),
            ("forwarded", b"for=127.0.0.1".as_slice()),
            ("x-forwarded-for", b"garbage".as_slice()),
            ("x-real-ip", b"127.0.0.1".as_slice()),
            ("via", b"1.1 apache".as_slice()),
            ("x-forwarded-proto", b"https".as_slice()),
        ] {
            let h = headers(&[("host", b"127.0.0.1:41721"), (name, value)]);
            assert!(!direct_loopback_request(sock("127.0.0.1:1"), &h, None), "{name}: {value:?}");
        }
    }

    /// Round-5 S-B1: the request's own host must be a loopback literal or
    /// `localhost` — a DNS-rebinding page sends its own name.
    #[test]
    fn admin_bypass_requires_a_loopback_host() {
        for host in [
            "127.0.0.1:41721",
            "127.0.0.1",
            "127.1.2.3:8080",
            "localhost:41721",
            "LOCALHOST:41721",
            "LocalHost",
            "[::1]:41721",
            "[::1]",
            "[0:0:0:0:0:0:0:1]:41721",
            "[::ffff:127.0.0.1]:41721",
        ] {
            assert!(bypass("127.0.0.1:1", &[("host", host.as_bytes())]), "{host} must pass");
        }
        for host in [
            "evil.example:41721",     // rebinding name
            "attacker.localhost:41721",
            "localhost.:41721",
            "127.0.0.1.nip.io:41721",
            "10.0.0.1:41721",
            "0.0.0.0:41721",
            "[::]:41721",
            "[2001:db8::1]:41721",
            "127.0.0.1:",
            "127.0.0.1:99999",
            "127.0.0.1:80:80",
            "127.1",
            "0x7f.0.0.1",
            "user@127.0.0.1",
            "::1",
            "[::1",
            "[::1]x",
            "",
        ] {
            assert!(!bypass("127.0.0.1:1", &[("host", host.as_bytes())]), "{host:?} must deny");
        }
        // Absent Host (and no :authority), repeated Host, non-UTF-8 Host.
        assert!(!bypass("127.0.0.1:1", &[]));
        assert!(!bypass("127.0.0.1:1", &[("host", b"127.0.0.1"), ("host", b"127.0.0.1")]));
        assert!(!bypass("127.0.0.1:1", &[("host", b"127.0.0.1\xff")]));
        // HTTP/2: no Host header, the :authority is used instead.
        assert!(direct_loopback_request(sock("127.0.0.1:1"), &headers(&[]), Some("127.0.0.1:41721")));
        assert!(!direct_loopback_request(sock("127.0.0.1:1"), &headers(&[]), Some("evil.example:41721")));
        // A Host header wins over the authority (both must not disagree
        // into a pass).
        assert!(!direct_loopback_request(
            sock("127.0.0.1:1"),
            &headers(&[("host", b"evil.example")]),
            Some("127.0.0.1:41721")
        ));
    }

    /// Round-5 S-B1: a browser page on another origin (the operator browsing
    /// on the node host) must not drive the admin API through loopback.
    #[test]
    fn admin_bypass_refuses_cross_origin_browser_requests() {
        let host: (&'static str, &[u8]) = ("host", b"127.0.0.1:41721");
        // Same-origin dashboard calls (POST carries Origin; ws upgrade too).
        assert!(bypass("127.0.0.1:1", &[host, ("origin", b"http://127.0.0.1:41721")]));
        assert!(bypass(
            "127.0.0.1:1",
            &[host, ("origin", b"http://127.0.0.1:41721"), ("sec-fetch-site", b"same-origin")]
        ));
        assert!(bypass(
            "127.0.0.1:1",
            &[("host", b"localhost:41721"), ("origin", b"HTTP://LOCALHOST:41721")]
        ));
        assert!(bypass("[::1]:1", &[("host", b"[::1]:41721"), ("origin", b"http://[::1]:41721")]));
        // Default ports: Origin omits them, Host may or may not.
        assert!(bypass("127.0.0.1:1", &[("host", b"127.0.0.1"), ("origin", b"http://127.0.0.1")]));
        assert!(bypass("127.0.0.1:1", &[("host", b"127.0.0.1:80"), ("origin", b"http://127.0.0.1")]));
        assert!(bypass("127.0.0.1:1", &[("host", b"127.0.0.1"), ("origin", b"https://127.0.0.1:443")]));
        // curl / scripts: no Origin, no fetch metadata.
        assert!(bypass("127.0.0.1:1", &[host]));
        // Typed URL / bookmark navigation.
        assert!(bypass("127.0.0.1:1", &[host, ("sec-fetch-site", b"none")]));
        for origin in [
            "http://evil.example",
            "http://evil.example:41721",
            "http://localhost:41721",   // other host spelling = other origin
            "http://127.0.0.1:3000",    // another local dev server
            "http://127.0.0.2:41721",
            "http://[::1]:41721",
            "https://127.0.0.1",        // 443 vs 41721
            "null",
            "file://",
            "ws://127.0.0.1:41721",
            "http://127.0.0.1:41721/",
            "http://user@127.0.0.1:41721",
            "",
        ] {
            assert!(!bypass("127.0.0.1:1", &[host, ("origin", origin.as_bytes())]), "Origin {origin:?} must deny");
        }
        // Repeated Origin.
        assert!(!bypass(
            "127.0.0.1:1",
            &[host, ("origin", b"http://127.0.0.1:41721"), ("origin", b"http://127.0.0.1:41721")]
        ));
        // Rebinding: Origin same-origin with a hostile Host is still denied
        // by the Host rule.
        assert!(!bypass(
            "127.0.0.1:1",
            &[("host", b"evil.example:41721"), ("origin", b"http://evil.example:41721")]
        ));
        // Fetch metadata says another site initiated it (older browsers may
        // also omit Origin on such GETs).
        for site in ["cross-site", "same-site", "CROSS-SITE", "bogus"] {
            assert!(!bypass("127.0.0.1:1", &[host, ("sec-fetch-site", site.as_bytes())]), "{site}");
        }
        assert!(!bypass(
            "127.0.0.1:1",
            &[host, ("sec-fetch-site", b"same-origin"), ("sec-fetch-site", b"same-origin")]
        ));
    }

    #[test]
    fn sec_fetch_site_gate() {
        assert!(sec_fetch_site_allows_admin(&headers(&[])));
        assert!(sec_fetch_site_allows_admin(&headers(&[("sec-fetch-site", b"same-origin")])));
        assert!(sec_fetch_site_allows_admin(&headers(&[("sec-fetch-site", b"none")])));
        assert!(!sec_fetch_site_allows_admin(&headers(&[("sec-fetch-site", b"same-site")])));
        assert!(!sec_fetch_site_allows_admin(&headers(&[("sec-fetch-site", b"cross-site")])));
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
