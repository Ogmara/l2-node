//! Hand-rolled SOCKS5 dialer for the external-Tor onion transport
//! (spec 13 §6.4, l2-node 0.46.9+).
//!
//! # Why hand-rolled?
//!
//! The audit surface is small (~100 LOC of protocol) and the security
//! properties — no DNS leak, no IP fallthrough, no untrusted bytes
//! interpreted — are easier to reason about with a focused
//! implementation than with a third-party SOCKS5 crate that we'd
//! have to vendor anyway. The protocol is RFC 1928, which is short
//! and stable; we implement only the CONNECT command, only the
//! no-authentication method, and only the hostname address type
//! (ATYP 0x03) — exactly what onion routing through Tor needs.
//!
//! # Security properties (audited in v0.46.9)
//!
//! 1. **No DNS leak.** [`Socks5Dialer::connect_via_hostname`] sends the
//!    target hostname to the SOCKS proxy as ATYP 0x03 (DOMAINNAME) —
//!    the Tor daemon does the resolution inside its onion overlay.
//!    The dialer never calls `getaddrinfo`/`tokio::net::lookup_host`/
//!    similar on a `.onion` target. There is no IP-target overload of
//!    `connect`: callers physically cannot bypass the hostname path.
//! 2. **No IP fallthrough on proxy failure.** If the proxy is
//!    unreachable, returns wrong protocol version bytes, refuses the
//!    CONNECT, etc. — the dialer surfaces the error and returns
//!    `Err`. It never falls back to a direct TCP connect.
//! 3. **Bounded reads.** Every wire-protocol read uses a fixed-size
//!    buffer matching the protocol message size. There is no
//!    attacker-controlled length field read into an unbounded
//!    allocation.
//! 4. **Loopback-only proxy.** Enforced at config-load
//!    (`Config::validate`), but [`Socks5Dialer::new`] also re-checks
//!    so an in-process caller cannot construct a non-loopback dialer
//!    accidentally.
//! 5. **Connect/read timeouts.** Every wire-protocol round trip is
//!    wrapped in a `tokio::time::timeout` so a stalled proxy cannot
//!    pin a caller task indefinitely.
//!
//! # Out of scope for v0.46.9
//!
//! - Outbound libp2p `Transport` integration (deferred to a future
//!   release; onion Phase 2, not a mainnet blocker).
//!   The dialer is shipped now so the SOCKS5 security boundary can
//!   be reviewed independently of the libp2p Transport-trait
//!   composition work.
//! - GSSAPI / username-password SOCKS auth. Tor's local SOCKS port
//!   accepts no-auth; remote authenticated proxies are out of scope.
//! - SOCKS5 BIND / UDP ASSOCIATE commands.
//!
//! # References
//!
//! - RFC 1928 — SOCKS Protocol Version 5
//! - tor.spec.txt §A.2 — Tor SOCKS extensions (we use only the
//!   subset compatible with RFC 1928)

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Default per-handshake timeout. The SOCKS5 handshake is tiny; if
/// the proxy doesn't respond in 5 seconds, treat the proxy as dead.
/// Caller can override via [`Socks5Dialer::with_handshake_timeout`].
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default connect timeout to the SOCKS proxy itself (the TCP dial
/// before the SOCKS handshake even starts). The proxy is on
/// loopback; if it's not accepting connections in 5 seconds, the
/// daemon is not running.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum length of a hostname accepted by [`Socks5Dialer::connect_via_hostname`].
/// RFC 1928 caps DOMAINNAME at 255 bytes; we enforce here as well so
/// caller bugs surface immediately rather than as opaque proxy
/// errors.
pub const MAX_HOSTNAME_LEN: usize = 255;

/// SOCKS5 dialer — connects to a target hostname through a loopback
/// SOCKS5 proxy (typically the local Tor daemon's `127.0.0.1:9050`).
#[derive(Debug, Clone)]
pub struct Socks5Dialer {
    proxy_addr: SocketAddr,
    connect_timeout: Duration,
    handshake_timeout: Duration,
}

impl Socks5Dialer {
    /// Construct a dialer pointing at the given SOCKS proxy.
    ///
    /// Refuses non-loopback proxy addresses with [`io::ErrorKind::InvalidInput`].
    /// `Config::validate` performs the same check at config-load, but
    /// this is the second line of defense for in-process constructors
    /// (tests, future callers).
    pub fn new(proxy_addr: SocketAddr) -> io::Result<Self> {
        if !proxy_addr.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "SOCKS5 proxy {proxy_addr} is not a loopback address — \
                     refuses to construct a dialer that would route onion \
                     traffic through a remote SOCKS server"
                ),
            ));
        }
        Ok(Self {
            proxy_addr,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        })
    }

    pub fn with_connect_timeout(mut self, t: Duration) -> Self {
        self.connect_timeout = t;
        self
    }

    pub fn with_handshake_timeout(mut self, t: Duration) -> Self {
        self.handshake_timeout = t;
        self
    }

    /// The configured SOCKS proxy address — exposed for diagnostic
    /// logging; the dialer never re-parses it.
    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr
    }

    /// CONNECT to `target_host:target_port` through the SOCKS5 proxy
    /// using the **hostname** address type (ATYP 0x03). The proxy
    /// resolves the hostname inside its overlay (for Tor, this is
    /// the onion service network); the dialer never resolves the
    /// hostname locally.
    ///
    /// On success returns the `TcpStream` connected to the SOCKS
    /// proxy, with the SOCKS handshake already completed — the
    /// caller speaks the target protocol on this stream directly.
    ///
    /// On any failure (proxy unreachable, handshake refused, target
    /// unreachable, malformed reply) returns `Err`. The dialer never
    /// falls back to a direct connect.
    pub async fn connect_via_hostname(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> io::Result<TcpStream> {
        // Length bound — keeps an over-long hostname from being sent
        // as bytes the proxy would interpret as a different ATYP.
        if target_host.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 target hostname is empty",
            ));
        }
        if target_host.len() > MAX_HOSTNAME_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "SOCKS5 target hostname is {} bytes; RFC 1928 cap is {}",
                    target_host.len(),
                    MAX_HOSTNAME_LEN
                ),
            ));
        }
        // ASCII / printable check — defends against accidentally
        // sending a control character that some proxies might
        // interpret as a separator. Tor accepts ASCII v3 onion
        // addresses; bytes outside ASCII never appear in practice.
        if !target_host.is_ascii() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 target hostname must be ASCII",
            ));
        }

        // ── Step 1: TCP-connect to the SOCKS proxy. ─────────────
        let mut stream = match timeout(
            self.connect_timeout,
            TcpStream::connect(self.proxy_addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("SOCKS5 proxy TCP connect to {} failed: {}",
                            self.proxy_addr, e),
                ));
            }
            Err(_elapsed) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "SOCKS5 proxy TCP connect to {} timed out after {:?}",
                        self.proxy_addr, self.connect_timeout
                    ),
                ));
            }
        };

        // ── Step 2: Method-selection request. ───────────────────
        // RFC 1928 §3:
        //   +----+----------+----------+
        //   |VER | NMETHODS | METHODS  |
        //   +----+----------+----------+
        //   | 1  |    1     | 1 to 255 |
        //   +----+----------+----------+
        // VER = 0x05 (SOCKS5), NMETHODS = 1, METHODS = [0x00 (no auth)].
        let method_req = [0x05u8, 0x01, 0x00];
        Self::write_all_timeout(&mut stream, &method_req, self.handshake_timeout).await?;

        // ── Step 3: Method-selection reply (2 bytes). ───────────
        // +----+--------+
        // |VER | METHOD |
        // +----+--------+
        let mut method_resp = [0u8; 2];
        Self::read_exact_timeout(&mut stream, &mut method_resp, self.handshake_timeout)
            .await?;
        if method_resp[0] != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "SOCKS5 proxy returned non-SOCKS5 version byte 0x{:02x}",
                    method_resp[0]
                ),
            ));
        }
        if method_resp[1] != 0x00 {
            // 0xFF = NO ACCEPTABLE METHODS; anything else is also a
            // refusal of the no-auth method we offered.
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "SOCKS5 proxy refused no-auth method (returned 0x{:02x}); \
                     authenticated SOCKS5 is not supported by this dialer",
                    method_resp[1]
                ),
            ));
        }

        // ── Step 4: CONNECT request with ATYP=0x03 (DOMAINNAME). ─
        // +----+-----+-------+------+----------+----------+
        // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+
        // For ATYP=0x03 DST.ADDR is: 1 byte length || hostname bytes.
        let host_bytes = target_host.as_bytes();
        let mut req = Vec::with_capacity(7 + host_bytes.len());
        req.push(0x05); // VER
        req.push(0x01); // CMD = CONNECT
        req.push(0x00); // RSV
        req.push(0x03); // ATYP = DOMAINNAME — NEVER resolved locally
        req.push(host_bytes.len() as u8);
        req.extend_from_slice(host_bytes);
        req.extend_from_slice(&target_port.to_be_bytes());
        Self::write_all_timeout(&mut stream, &req, self.handshake_timeout).await?;

        // ── Step 5: CONNECT reply. ──────────────────────────────
        // First 4 bytes: VER | REP | RSV | ATYP. We then read the
        // bound-address (variable per ATYP) and 2 bytes BND.PORT.
        let mut hdr = [0u8; 4];
        Self::read_exact_timeout(&mut stream, &mut hdr, self.handshake_timeout).await?;
        if hdr[0] != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "SOCKS5 CONNECT reply VER = 0x{:02x}, expected 0x05",
                    hdr[0]
                ),
            ));
        }
        if hdr[1] != 0x00 {
            // REP codes per RFC 1928 §6:
            //   0x01 general SOCKS server failure
            //   0x02 connection not allowed by ruleset
            //   0x03 network unreachable
            //   0x04 host unreachable
            //   0x05 connection refused
            //   0x06 TTL expired
            //   0x07 command not supported
            //   0x08 address type not supported
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "SOCKS5 proxy refused CONNECT to {}:{} with REP=0x{:02x}",
                    target_host, target_port, hdr[1]
                ),
            ));
        }
        // Drain the bound-address payload — we don't use it for
        // anything, but a half-consumed reply would desync the
        // stream so we must read it through. Length depends on ATYP.
        let atyp = hdr[3];
        let bnd_addr_len = match atyp {
            0x01 => 4, // IPv4
            0x04 => 16, // IPv6
            0x03 => {
                // 1-byte length prefix + that many bytes
                let mut len_byte = [0u8; 1];
                Self::read_exact_timeout(&mut stream, &mut len_byte, self.handshake_timeout)
                    .await?;
                len_byte[0] as usize
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("SOCKS5 reply has unknown ATYP 0x{other:02x}"),
                ));
            }
        };
        // Hard cap on bound-address length to prevent a hostile proxy
        // from advertising a giant payload that would stall the
        // handshake. RFC max is 255 (domain name length byte).
        if bnd_addr_len > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("SOCKS5 reply BND.ADDR length {bnd_addr_len} exceeds cap"),
            ));
        }
        let mut bnd_addr = vec![0u8; bnd_addr_len];
        if bnd_addr_len > 0 {
            Self::read_exact_timeout(&mut stream, &mut bnd_addr, self.handshake_timeout)
                .await?;
        }
        let mut bnd_port = [0u8; 2];
        Self::read_exact_timeout(&mut stream, &mut bnd_port, self.handshake_timeout)
            .await?;

        // Handshake complete. The stream is now a transparent
        // TCP-over-onion channel — caller speaks the target protocol.
        Ok(stream)
    }

    async fn write_all_timeout(
        s: &mut TcpStream,
        buf: &[u8],
        t: Duration,
    ) -> io::Result<()> {
        match timeout(t, s.write_all(buf)).await {
            Ok(r) => r,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SOCKS5 write timed out",
            )),
        }
    }

    async fn read_exact_timeout(
        s: &mut TcpStream,
        buf: &mut [u8],
        t: Duration,
    ) -> io::Result<()> {
        match timeout(t, s.read_exact(buf)).await {
            Ok(r) => r.map(|_| ()),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SOCKS5 read timed out",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    /// Start a mock SOCKS5 server on a loopback port. The provided
    /// closure receives the accepted [`TcpStream`] for one connection
    /// and runs the protocol script. Returns the server's bound
    /// address.
    async fn spawn_mock<F, Fut>(handler: F) -> SocketAddr
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handler(stream).await;
        });
        addr
    }

    #[tokio::test]
    async fn rejects_non_loopback_proxy() {
        let err = Socks5Dialer::new("8.8.8.8:9050".parse().unwrap()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let msg = err.to_string();
        assert!(msg.contains("not a loopback"), "msg = {msg}");
    }

    #[tokio::test]
    async fn rejects_empty_hostname() {
        // Bind a listener so the dial succeeds, but the hostname check
        // fires before any byte is written.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = proxy.local_addr().unwrap();
        let dialer = Socks5Dialer::new(addr).unwrap();
        let err = dialer.connect_via_hostname("", 80).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn rejects_overlong_hostname() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = proxy.local_addr().unwrap();
        let dialer = Socks5Dialer::new(addr).unwrap();
        let long = "a".repeat(MAX_HOSTNAME_LEN + 1);
        let err = dialer.connect_via_hostname(&long, 80).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn rejects_non_ascii_hostname() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = proxy.local_addr().unwrap();
        let dialer = Socks5Dialer::new(addr).unwrap();
        let err = dialer
            .connect_via_hostname("ünicode.example", 80)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn proxy_unreachable_returns_err_no_fallthrough() {
        // Pick an unbound loopback port. Construct the dialer with a
        // 100ms connect timeout so the test is fast.
        // (Port 1 is reserved for tcpmux which is virtually never
        // listening on a developer machine.)
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let dialer = Socks5Dialer::new(addr)
            .unwrap()
            .with_connect_timeout(Duration::from_millis(100));
        let err = dialer
            .connect_via_hostname("any.onion", 80)
            .await
            .unwrap_err();
        // ConnectionRefused or TimedOut depending on the kernel — both
        // are acceptable. The critical assertion is: NO direct connect
        // to "any.onion" was attempted (which would have failed with a
        // DNS resolution error instead).
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::TimedOut
            ),
            "expected ConnRefused or TimedOut, got {:?} ({})",
            err.kind(),
            err
        );
    }

    #[tokio::test]
    async fn proxy_returns_wrong_version_fails() {
        let addr = spawn_mock(|mut s| async move {
            // Send a non-SOCKS5 version byte as the method-selection
            // reply. Real-world: a misconfigured proxy that's actually
            // an HTTP server.
            let _ = s.write_all(&[0xff, 0x00]).await;
        })
        .await;
        let dialer = Socks5Dialer::new(addr).unwrap();
        let err = dialer
            .connect_via_hostname("x.onion", 80)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("non-SOCKS5"));
    }

    #[tokio::test]
    async fn proxy_refuses_method_fails() {
        let addr = spawn_mock(|mut s| async move {
            // SOCKS5 method-selection: 0xFF = no acceptable methods.
            let _ = s.write_all(&[0x05, 0xff]).await;
        })
        .await;
        let dialer = Socks5Dialer::new(addr).unwrap();
        let err = dialer
            .connect_via_hostname("x.onion", 80)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn proxy_refuses_connect_fails() {
        let addr = spawn_mock(|mut s| async move {
            // Method-selection ok.
            let _ = s.write_all(&[0x05, 0x00]).await;
            // Drain the CONNECT request.
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf).await;
            // REP = 0x05 (connection refused), IPv4 bound, 0.0.0.0:0.
            let _ = s
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
        })
        .await;
        let dialer = Socks5Dialer::new(addr).unwrap();
        let err = dialer
            .connect_via_hostname("x.onion", 80)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[tokio::test]
    async fn full_handshake_succeeds_and_forwards_bytes() {
        // The most important positive test — the proxy speaks valid
        // SOCKS5 and the dialer returns a stream we can send/receive
        // on. We use ATYP=0x01 (IPv4) in the reply because that's the
        // simplest valid path.
        let received = Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));
        let recv_clone = Arc::clone(&received);
        let addr = spawn_mock(move |mut s| async move {
            // Method-selection.
            let mut mreq = [0u8; 3];
            let _ = s.read_exact(&mut mreq).await;
            assert_eq!(mreq, [0x05, 0x01, 0x00]);
            let _ = s.write_all(&[0x05, 0x00]).await;
            // CONNECT request: VER, CMD, RSV, ATYP, LEN, host, port.
            let mut prefix = [0u8; 5];
            let _ = s.read_exact(&mut prefix).await;
            assert_eq!(prefix[0], 0x05);
            assert_eq!(prefix[1], 0x01); // CONNECT
            assert_eq!(prefix[3], 0x03); // ATYP = DOMAINNAME
            let host_len = prefix[4] as usize;
            let mut host = vec![0u8; host_len];
            let _ = s.read_exact(&mut host).await;
            let mut port = [0u8; 2];
            let _ = s.read_exact(&mut port).await;
            assert_eq!(host, b"example.onion");
            assert_eq!(u16::from_be_bytes(port), 41720);
            // CONNECT reply: VER, REP=0, RSV, ATYP=1 IPv4, BND.ADDR
            // (4 bytes), BND.PORT (2 bytes).
            let _ = s
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await;
            // After handshake, the proxy normally forwards bytes to
            // the target. The mock just echoes what it reads next
            // back into the `received` log so the test can verify the
            // dialer sent the expected payload.
            let mut buf = [0u8; 16];
            if let Ok(n) = s.read(&mut buf).await {
                recv_clone.lock().await.extend_from_slice(&buf[..n]);
            }
        })
        .await;
        let dialer = Socks5Dialer::new(addr).unwrap();
        let mut stream = dialer
            .connect_via_hostname("example.onion", 41720)
            .await
            .expect("handshake must succeed");
        // Send a payload across the now-established tunnel.
        stream.write_all(b"hello").await.unwrap();
        // Allow the mock task to consume.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let got = received.lock().await.clone();
        assert_eq!(got, b"hello");
    }

    #[tokio::test]
    async fn ipv4_bound_address_consumed_correctly() {
        // Verifies the ATYP-1 path reads exactly 4+2 BND bytes.
        let addr = spawn_mock(|mut s| async move {
            let _ = s.write_all(&[0x05, 0x00]).await;
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 1, 0])
                .await;
            // No further bytes.
        })
        .await;
        let dialer = Socks5Dialer::new(addr).unwrap();
        let _ = dialer
            .connect_via_hostname("y.onion", 80)
            .await
            .expect("ipv4 bound address path");
    }

    #[tokio::test]
    async fn ipv6_bound_address_consumed_correctly() {
        let addr = spawn_mock(|mut s| async move {
            let _ = s.write_all(&[0x05, 0x00]).await;
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf).await;
            // ATYP=4 IPv6, 16 bytes addr, 2 bytes port.
            let mut reply: Vec<u8> = vec![0x05, 0x00, 0x00, 0x04];
            reply.extend_from_slice(&[0u8; 16]);
            reply.extend_from_slice(&[0u8; 2]);
            let _ = s.write_all(&reply).await;
        })
        .await;
        let dialer = Socks5Dialer::new(addr).unwrap();
        let _ = dialer
            .connect_via_hostname("z.onion", 80)
            .await
            .expect("ipv6 bound address path");
    }

    #[tokio::test]
    async fn domainname_bound_address_consumed_correctly() {
        let addr = spawn_mock(|mut s| async move {
            let _ = s.write_all(&[0x05, 0x00]).await;
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf).await;
            // ATYP=3 DOMAINNAME, 1 length byte = 5, "abcde", port.
            let mut reply: Vec<u8> =
                vec![0x05, 0x00, 0x00, 0x03, 0x05, b'a', b'b', b'c', b'd', b'e'];
            reply.extend_from_slice(&[0u8; 2]);
            let _ = s.write_all(&reply).await;
        })
        .await;
        let dialer = Socks5Dialer::new(addr).unwrap();
        let _ = dialer
            .connect_via_hostname("w.onion", 80)
            .await
            .expect("domainname bound address path");
    }

    #[tokio::test]
    async fn unknown_atyp_in_reply_fails() {
        let addr = spawn_mock(|mut s| async move {
            let _ = s.write_all(&[0x05, 0x00]).await;
            let mut buf = [0u8; 256];
            let _ = s.read(&mut buf).await;
            // ATYP=0xff — not defined.
            let _ = s.write_all(&[0x05, 0x00, 0x00, 0xff, 0, 0]).await;
        })
        .await;
        let dialer = Socks5Dialer::new(addr).unwrap();
        let err = dialer
            .connect_via_hostname("q.onion", 80)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("unknown ATYP"));
    }
}
