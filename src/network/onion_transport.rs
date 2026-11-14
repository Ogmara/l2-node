//! Outbound `/onion3/...` libp2p transport (spec 13 §6.4.1, onion Phase 2,
//! l2-node 0.146.0+).
//!
//! Wraps the hand-rolled SOCKS5 dialer in [`super::tor`] as a libp2p
//! [`Transport`] so onion multiaddrs from the SC registry, the persisted
//! peer book or `bootstrap_nodes` become dialable. The raw stream it
//! returns goes through the same Noise + yamux upgrade as TCP, so the
//! peer is authenticated by its libp2p identity exactly like a clearnet
//! connection.
//!
//! # Security properties
//!
//! - **Only `/onion3/<addr>[/p2p/<peer>]` is accepted.** Every other
//!   multiaddr, including onion addresses with extra protocol segments,
//!   returns [`TransportError::MultiaddrNotSupported`] so the swarm hands
//!   it to the clearnet transports instead. The reverse also holds: TCP,
//!   QUIC and DNS never accept `/onion3`, so an onion address can only
//!   ever leave through the SOCKS proxy. There is no fallback path.
//! - **No local resolution.** The target is forwarded to Tor as a
//!   hostname (ATYP 0x03, see [`super::tor`]); nothing here calls a
//!   resolver.
//! - **Disabled means inert.** With `[network.tor] enabled = false` the
//!   transport is still registered (it keeps the swarm builder's type the
//!   same) but refuses every address, which is the pre-Phase-2 behaviour.
//! - **Outbound only.** Inbound onion traffic arrives through the Tor
//!   daemon's hidden-service forward onto the loopback TCP listener
//!   opened in `NetworkService::new`, so `listen_on` refuses everything.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::future::{BoxFuture, FutureExt};
use libp2p::core::transport::{DialOpts, ListenerId, Transport, TransportError, TransportEvent};
use libp2p::multiaddr::Protocol;
use libp2p::tcp::tokio::TcpStream;
use libp2p::Multiaddr;

use super::tor::Socks5Dialer;

/// How long to wait for each SOCKS5 round trip, including the CONNECT
/// reply. Tor only answers CONNECT once the rendezvous circuit to the
/// hidden service is built, which routinely takes 5-30 s, so the dialer's
/// 5 s default would fail most real onion dials. 60 s stays well under
/// Tor's own `SocksTimeout` (120 s).
pub const ONION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Upper bound on one whole onion dial (proxy connect plus every SOCKS5
/// round trip). The per-round-trip bound alone would let a stalled proxy
/// hold a dial for several minutes.
pub const ONION_DIAL_TIMEOUT: Duration = Duration::from_secs(90);

/// libp2p transport that dials `/onion3` multiaddrs through the local Tor
/// SOCKS5 proxy. See the module docs for the security properties.
pub struct OnionTransport {
    /// `None` when `[network.tor] enabled = false`: every dial is refused.
    dialer: Option<Socks5Dialer>,
}

impl OnionTransport {
    /// Build the transport. Pass `None` to register it in its disabled
    /// state.
    pub fn new(dialer: Option<Socks5Dialer>) -> Self {
        Self { dialer }
    }
}

impl Transport for OnionTransport {
    type Output = TcpStream;
    type Error = io::Error;
    type ListenerUpgrade = futures::future::Pending<Result<Self::Output, Self::Error>>;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn listen_on(
        &mut self,
        _id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn remove_listener(&mut self, _id: ListenerId) -> bool {
        false
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        _opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let Some(dialer) = self.dialer.clone() else {
            return Err(TransportError::MultiaddrNotSupported(addr));
        };
        let Some((host, port)) = onion_target(&addr) else {
            return Err(TransportError::MultiaddrNotSupported(addr));
        };
        Ok(async move {
            match tokio::time::timeout(ONION_DIAL_TIMEOUT, dialer.connect_via_hostname(&host, port))
                .await
            {
                Ok(result) => result.map(TcpStream),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("onion dial to {host}:{port} timed out after {ONION_DIAL_TIMEOUT:?}"),
                )),
            }
        }
        .boxed())
    }

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        // No listeners, so there is never an event to report.
        Poll::Pending
    }
}

/// Extract `("<base32>.onion", port)` from `/onion3/<addr>[/p2p/<peer>]`.
///
/// Returns `None` for anything else: a non-onion first segment, a second
/// onion or transport segment, or any trailing protocol other than one
/// `/p2p`. Being strict keeps a crafted address from smuggling extra
/// semantics past the transport selection.
fn onion_target(addr: &Multiaddr) -> Option<(String, u16)> {
    let mut iter = addr.iter();
    let Protocol::Onion3(onion) = iter.next()? else {
        return None;
    };
    match iter.next() {
        None | Some(Protocol::P2p(_)) => {}
        Some(_) => return None,
    }
    if iter.next().is_some() {
        return None;
    }
    let port = onion.port();
    if port == 0 {
        return None;
    }
    Some((format!("{}.onion", base32_lower(onion.hash())), port))
}

/// RFC 4648 base32, lowercase, unpadded — the alphabet Tor uses for v3
/// onion hostnames. A 35-byte onion address encodes to exactly 56 chars.
fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u16::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[usize::from((buffer >> bits) & 0x1f)] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[usize::from((buffer << (5 - bits)) & 0x1f)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A real v3 onion hostname (the Tor Project's), 56 base32 chars.
    const ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid";

    fn dial_opts() -> DialOpts {
        DialOpts {
            role: libp2p::core::Endpoint::Dialer,
            port_use: libp2p::core::transport::PortUse::New,
        }
    }

    #[test]
    fn base32_matches_rfc4648_vectors() {
        assert_eq!(base32_lower(b""), "");
        assert_eq!(base32_lower(b"f"), "my");
        assert_eq!(base32_lower(b"fo"), "mzxq");
        assert_eq!(base32_lower(b"foo"), "mzxw6");
        assert_eq!(base32_lower(b"foob"), "mzxw6yq");
        assert_eq!(base32_lower(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_lower(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn onion_target_round_trips_the_hostname() {
        let addr: Multiaddr = format!("/onion3/{ONION}:41720").parse().unwrap();
        assert_eq!(onion_target(&addr), Some((format!("{ONION}.onion"), 41720)));
    }

    #[test]
    fn onion_target_accepts_a_trailing_peer_id() {
        let peer = libp2p::PeerId::random();
        let addr: Multiaddr = format!("/onion3/{ONION}:41720/p2p/{peer}").parse().unwrap();
        assert_eq!(onion_target(&addr), Some((format!("{ONION}.onion"), 41720)));
    }

    #[test]
    fn onion_target_rejects_everything_else() {
        let peer = libp2p::PeerId::random();
        for s in [
            "/ip4/127.0.0.1/tcp/41720".to_string(),
            "/dns4/example.org/tcp/41720".to_string(),
            format!("/onion3/{ONION}:41720/tcp/80"),
            format!("/onion3/{ONION}:41720/p2p/{peer}/p2p/{peer}"),
            format!("/ip4/1.2.3.4/tcp/1/onion3/{ONION}:41720"),
        ] {
            let addr: Multiaddr = s.parse().unwrap();
            assert_eq!(onion_target(&addr), None, "{s}");
        }
    }

    #[test]
    fn disabled_transport_refuses_onion_addresses() {
        let mut t = OnionTransport::new(None);
        let addr: Multiaddr = format!("/onion3/{ONION}:41720").parse().unwrap();
        assert!(matches!(
            t.dial(addr, dial_opts()),
            Err(TransportError::MultiaddrNotSupported(_))
        ));
    }

    #[test]
    fn enabled_transport_refuses_clearnet_and_all_listens() {
        let dialer = Socks5Dialer::new("127.0.0.1:9050".parse().unwrap()).unwrap();
        let mut t = OnionTransport::new(Some(dialer));
        let clearnet: Multiaddr = "/ip4/127.0.0.1/tcp/41720".parse().unwrap();
        assert!(matches!(
            t.dial(clearnet.clone(), dial_opts()),
            Err(TransportError::MultiaddrNotSupported(_))
        ));
        assert!(matches!(
            t.listen_on(ListenerId::next(), clearnet),
            Err(TransportError::MultiaddrNotSupported(_))
        ));
    }

    /// End to end against a fake SOCKS5 proxy: the CONNECT request must
    /// carry the onion hostname as a DOMAINNAME (never resolved locally),
    /// and bytes must then flow over the returned stream.
    #[tokio::test]
    async fn dial_sends_the_hostname_through_the_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 5];
            s.read_exact(&mut head).await.unwrap();
            assert_eq!(&head[..4], &[0x05, 0x01, 0x00, 0x03]);
            let mut host = vec![0u8; head[4] as usize];
            s.read_exact(&mut host).await.unwrap();
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            s.write_all(b"hello").await.unwrap();
            (String::from_utf8(host).unwrap(), u16::from_be_bytes(port))
        });

        let dialer = Socks5Dialer::new(proxy_addr).unwrap();
        let mut t = OnionTransport::new(Some(dialer));
        let addr: Multiaddr = format!("/onion3/{ONION}:41720").parse().unwrap();
        let TcpStream(mut stream) = t.dial(addr, dial_opts()).unwrap().await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        let (host, port) = proxy.await.unwrap();
        assert_eq!(host, format!("{ONION}.onion"));
        assert_eq!(port, 41720);
    }

    /// Full stack: a swarm whose only transport is the upgraded onion
    /// transport dials `/onion3/.../p2p/<peer>`; a fake SOCKS5 proxy
    /// relays the stream to a second swarm's TCP listener (standing in
    /// for Tor plus the hidden-service forward). The connection must come
    /// up with Noise authenticating exactly the expected peer.
    #[tokio::test]
    async fn swarm_connects_over_onion_with_noise_peer_auth() {
        use futures::StreamExt;
        use libp2p::swarm::{dummy, SwarmEvent};
        use libp2p::SwarmBuilder;

        let idle = |c: libp2p::swarm::Config| {
            c.with_idle_connection_timeout(Duration::from_secs(30))
        };
        let mut server = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| dummy::Behaviour)
            .unwrap()
            .with_swarm_config(idle)
            .build();
        let server_peer = *server.local_peer_id();
        server.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        let server_port = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
                let Some(Protocol::Tcp(port)) = address.iter().nth(1) else { continue };
                break port;
            }
        };

        // Fake Tor: answer the SOCKS5 handshake, then splice the stream
        // onto the server's loopback listener.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = proxy.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 5];
            s.read_exact(&mut head).await.unwrap();
            let mut rest = vec![0u8; head[4] as usize + 2];
            s.read_exact(&mut rest).await.unwrap();
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut upstream = tokio::net::TcpStream::connect(("127.0.0.1", server_port))
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut s, &mut upstream).await;
        });

        let dialer = Socks5Dialer::new(proxy_addr).unwrap();
        let mut client = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_other_transport(|keypair| {
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    OnionTransport::new(Some(dialer))
                        .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                        .authenticate(libp2p::noise::Config::new(keypair)?)
                        .multiplex(libp2p::yamux::Config::default()),
                )
            })
            .unwrap()
            .with_behaviour(|_| dummy::Behaviour)
            .unwrap()
            .with_swarm_config(idle)
            .build();
        let target: Multiaddr = format!("/onion3/{ONION}:41720/p2p/{server_peer}")
            .parse()
            .unwrap();
        client.dial(target).unwrap();

        let connected = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                tokio::select! {
                    ev = client.select_next_some() => match ev {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => break peer_id,
                        SwarmEvent::OutgoingConnectionError { error, .. } => {
                            panic!("onion dial failed: {error}")
                        }
                        _ => {}
                    },
                    _ = server.select_next_some() => {}
                }
            }
        })
        .await
        .expect("onion connection timed out");
        assert_eq!(connected, server_peer);
    }

    /// A `/p2p` suffix naming a different peer than the one that answers
    /// must fail after Noise (libp2p's `WrongPeerId`), never connect.
    #[tokio::test]
    async fn swarm_rejects_onion_peer_with_wrong_identity() {
        use futures::StreamExt;
        use libp2p::swarm::{dummy, DialError, SwarmEvent};
        use libp2p::SwarmBuilder;

        let mut server = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| dummy::Behaviour)
            .unwrap()
            .build();
        server.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
        let server_port = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
                let Some(Protocol::Tcp(port)) = address.iter().nth(1) else { continue };
                break port;
            }
        };

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = proxy.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 5];
            s.read_exact(&mut head).await.unwrap();
            let mut rest = vec![0u8; head[4] as usize + 2];
            s.read_exact(&mut rest).await.unwrap();
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut upstream = tokio::net::TcpStream::connect(("127.0.0.1", server_port))
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut s, &mut upstream).await;
        });

        let dialer = Socks5Dialer::new(proxy_addr).unwrap();
        let mut client = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_other_transport(|keypair| {
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    OnionTransport::new(Some(dialer))
                        .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                        .authenticate(libp2p::noise::Config::new(keypair)?)
                        .multiplex(libp2p::yamux::Config::default()),
                )
            })
            .unwrap()
            .with_behaviour(|_| dummy::Behaviour)
            .unwrap()
            .build();
        let impostor = libp2p::PeerId::random();
        let target: Multiaddr = format!("/onion3/{ONION}:41720/p2p/{impostor}")
            .parse()
            .unwrap();
        client.dial(target).unwrap();

        let error = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                tokio::select! {
                    ev = client.select_next_some() => match ev {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            panic!("connected to {peer_id} despite the wrong /p2p id")
                        }
                        SwarmEvent::OutgoingConnectionError { error, .. } => break error,
                        _ => {}
                    },
                    _ = server.select_next_some() => {}
                }
            }
        })
        .await
        .expect("dial neither failed nor connected");
        assert!(matches!(error, DialError::WrongPeerId { .. }), "{error}");
    }
}
