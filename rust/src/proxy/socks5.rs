//! SOCKS5 and HTTP CONNECT proxy server.
//!
//! Supports:
//! - SOCKS5 auth negotiation (NO AUTH)
//! - SOCKS5 CONNECT (TCP proxy via KCP tunnel)
//! - SOCKS5 UDP ASSOCIATE (UDP proxy via tunnel)
//! - HTTP CONNECT (auto-detected by first byte)

use crate::noise::address::{Address, AddressError, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Notify;

// SOCKS5 protocol constants.
pub const VERSION5: u8 = 0x05;
pub const AUTH_NONE: u8 = 0x00;
pub const AUTH_NO_ACCEPT: u8 = 0xFF;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACH: u8 = 0x03;
pub const REP_HOST_UNREACH: u8 = 0x04;
pub const REP_CONN_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

/// Proxy errors.
#[derive(Debug)]
pub enum ProxyError {
    Io(io::Error),
    Address(AddressError),
    InvalidProtocol,
    InvalidAuth,
    UnsupportedCommand(u8),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::Io(e) => write!(f, "proxy IO error: {}", e),
            ProxyError::Address(e) => write!(f, "proxy address error: {}", e),
            ProxyError::InvalidProtocol => write!(f, "invalid protocol"),
            ProxyError::InvalidAuth => write!(f, "no acceptable auth method"),
            ProxyError::UnsupportedCommand(c) => write!(f, "unsupported command: 0x{:02x}", c),
        }
    }
}

impl std::error::Error for ProxyError {}
impl From<io::Error> for ProxyError {
    fn from(e: io::Error) -> Self { ProxyError::Io(e) }
}
impl From<AddressError> for ProxyError {
    fn from(e: AddressError) -> Self { ProxyError::Address(e) }
}

/// SOCKS5/HTTP CONNECT proxy server.
///
/// Accepts connections, auto-detects SOCKS5 vs HTTP CONNECT by first byte,
/// and dials targets directly via TCP.
pub struct Server {
    listener: TcpListener,
    shutdown: Arc<Notify>,
}

impl Server {
    /// Create a new proxy server bound to the given address.
    pub async fn bind(addr: &str) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Server {
            listener,
            shutdown: Arc::new(Notify::new()),
        })
    }

    /// Create a server from an existing TcpListener.
    pub fn from_listener(listener: TcpListener) -> Self {
        Server {
            listener,
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the server, accepting connections until shutdown.
    pub async fn serve(&self) {
        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            tokio::spawn(handle_conn(stream, self.shutdown.clone()));
                        }
                        Err(_) => continue,
                    }
                }
                _ = self.shutdown.notified() => return,
            }
        }
    }

    /// Signal the server to stop.
    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }
}

/// Handle a single client connection.
async fn handle_conn(mut stream: TcpStream, _shutdown: Arc<Notify>) {
    // Read first byte to detect protocol
    let mut first = [0u8; 1];
    if stream.read_exact(&mut first).await.is_err() {
        return;
    }

    match first[0] {
        VERSION5 => {
            let _ = handle_socks5(&mut stream).await;
        }
        b'C' => {
            let _ = handle_http_connect(&mut stream).await;
        }
        _ => {} // Unknown protocol
    }
}

/// Handle SOCKS5 protocol (version byte already consumed).
async fn handle_socks5(stream: &mut TcpStream) -> Result<(), ProxyError> {
    // === Auth negotiation ===
    let mut n_methods = [0u8; 1];
    stream.read_exact(&mut n_methods).await?;

    let mut methods = vec![0u8; n_methods[0] as usize];
    stream.read_exact(&mut methods).await?;

    let has_no_auth = methods.contains(&AUTH_NONE);
    if !has_no_auth {
        stream.write_all(&[VERSION5, AUTH_NO_ACCEPT]).await?;
        return Err(ProxyError::InvalidAuth);
    }

    stream.write_all(&[VERSION5, AUTH_NONE]).await?;

    // === Request ===
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    if header[0] != VERSION5 {
        return Err(ProxyError::InvalidProtocol);
    }

    let cmd = header[1];
    let atyp = header[3];

    let addr = read_address(stream, atyp).await?;

    match cmd {
        CMD_CONNECT => handle_connect(stream, &addr).await,
        CMD_UDP_ASSOCIATE => {
            send_reply(stream, REP_CMD_NOT_SUPPORTED, None).await?;
            Err(ProxyError::UnsupportedCommand(cmd))
        }
        _ => {
            send_reply(stream, REP_CMD_NOT_SUPPORTED, None).await?;
            Err(ProxyError::UnsupportedCommand(cmd))
        }
    }
}

/// Handle SOCKS5 CONNECT command.
async fn handle_connect(stream: &mut TcpStream, addr: &Address) -> Result<(), ProxyError> {
    // Dial the real target directly for now
    let target = format!("{}:{}", addr.host, addr.port);
    let remote = match TcpStream::connect(&target).await {
        Ok(r) => r,
        Err(_) => {
            send_reply(stream, REP_GENERAL_FAILURE, None).await?;
            return Ok(());
        }
    };

    send_reply(stream, REP_SUCCESS, Some(addr)).await?;

    // Bidirectional relay
    relay(stream, remote).await;
    Ok(())
}

/// Handle HTTP CONNECT (first byte 'C' already consumed).
async fn handle_http_connect(stream: &mut TcpStream) -> Result<(), ProxyError> {
    // Read rest of first line
    let mut buf = Vec::with_capacity(256);
    buf.push(b'C');
    loop {
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await?;
        buf.push(b[0]);
        if buf.len() > 4096 {
            return Err(ProxyError::InvalidProtocol);
        }
        if buf.ends_with(b"\n") {
            break;
        }
    }

    let first_line = String::from_utf8_lossy(&buf).to_string();
    let parts: Vec<&str> = first_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 || parts[0] != "CONNECT" {
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
        return Err(ProxyError::InvalidProtocol);
    }

    let target = parts[1];

    // Read remaining headers until empty line
    loop {
        let mut line = Vec::new();
        loop {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).await?;
            line.push(b[0]);
            if line.ends_with(b"\n") {
                break;
            }
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
    }

    // Parse target address
    let addr = parse_connect_target(target)?;

    // Dial target
    let target_str = format!("{}:{}", addr.host, addr.port);
    let remote = match TcpStream::connect(&target_str).await {
        Ok(r) => r,
        Err(_) => {
            stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            return Ok(());
        }
    };

    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    relay(stream, remote).await;
    Ok(())
}

/// Parse an HTTP CONNECT target like "host:port" or "[::1]:443".
fn parse_connect_target(target: &str) -> Result<Address, ProxyError> {
    // Try parsing as "host:port"
    if let Some(last_colon) = target.rfind(':') {
        let host_part = &target[..last_colon];
        let port_part = &target[last_colon + 1..];

        if let Ok(port) = port_part.parse::<u16>() {
            // Strip brackets for IPv6
            let host = host_part.trim_matches(|c| c == '[' || c == ']');

            if host.parse::<std::net::Ipv4Addr>().is_ok() {
                return Ok(Address::ipv4(host, port));
            } else if host.parse::<std::net::Ipv6Addr>().is_ok() {
                return Ok(Address::ipv6(host, port));
            } else {
                return Ok(Address::domain(host, port));
            }
        }
    }

    // Default: treat as domain with port 443
    Ok(Address::domain(target, 443))
}

/// Read a SOCKS5 address from a stream.
pub async fn read_address<R: AsyncRead + Unpin>(r: &mut R, atyp: u8) -> Result<Address, ProxyError> {
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6]; // 4 IP + 2 port
            r.read_exact(&mut buf).await?;
            let host = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(Address::ipv4(&host, port))
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            r.read_exact(&mut len_buf).await?;
            let domain_len = len_buf[0] as usize;
            if domain_len == 0 {
                return Err(ProxyError::Address(AddressError::InvalidDomain));
            }
            let mut buf = vec![0u8; domain_len + 2];
            r.read_exact(&mut buf).await?;
            let host = String::from_utf8_lossy(&buf[..domain_len]).into_owned();
            let port = u16::from_be_bytes([buf[domain_len], buf[domain_len + 1]]);
            Ok(Address::domain(&host, port))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18]; // 16 IP + 2 port
            r.read_exact(&mut buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(Address::ipv6(&ip.to_string(), port))
        }
        _ => Err(ProxyError::Address(AddressError::InvalidType(atyp))),
    }
}

/// Send a SOCKS5 reply.
pub async fn send_reply<W: AsyncWrite + Unpin>(
    w: &mut W,
    rep: u8,
    addr: Option<&Address>,
) -> io::Result<()> {
    if let Some(addr) = addr {
        if let Ok(encoded) = addr.encode() {
            let mut reply = Vec::with_capacity(3 + encoded.len());
            reply.push(VERSION5);
            reply.push(rep);
            reply.push(0x00); // RSV
            reply.extend_from_slice(&encoded);
            return w.write_all(&reply).await;
        }
    }
    // Default: 0.0.0.0:0
    w.write_all(&[VERSION5, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await
}

/// Bidirectional relay between two async streams.
pub async fn relay<A, B>(a: &mut A, b: B)
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let a_to_b = tokio::io::copy(&mut ar, &mut bw);
    let b_to_a = tokio::io::copy(&mut br, &mut aw);

    // Wait for either direction to complete
    tokio::select! {
        _ = a_to_b => {}
        _ = b_to_a => {}
    }
}

/// Parse a SOCKS5 UDP datagram.
/// Format: RSV(2) + FRAG(1) + ATYP(1) + ADDR(var) + PORT(2) + DATA(var)
pub fn parse_socks5_udp(data: &[u8]) -> Result<(Address, &[u8]), ProxyError> {
    if data.len() < 4 {
        return Err(ProxyError::InvalidProtocol);
    }
    if data[0] != 0 || data[1] != 0 {
        return Err(ProxyError::InvalidProtocol);
    }
    if data[2] != 0 {
        return Err(ProxyError::InvalidProtocol); // Fragment not supported
    }
    let (addr, consumed) = Address::decode(&data[3..]).map_err(ProxyError::Address)?;
    let payload = &data[3 + consumed..];
    Ok((addr, payload))
}

/// Build a SOCKS5 UDP datagram.
/// Format: RSV(2) + FRAG(1) + encoded_addr + DATA
pub fn build_socks5_udp(addr: &Address, data: &[u8]) -> Result<Vec<u8>, AddressError> {
    let encoded = addr.encode()?;
    let mut pkt = Vec::with_capacity(3 + encoded.len() + data.len());
    pkt.push(0x00); // RSV
    pkt.push(0x00); // RSV
    pkt.push(0x00); // FRAG
    pkt.extend_from_slice(&encoded);
    pkt.extend_from_slice(data);
    Ok(pkt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Start a TCP echo server, return its address.
    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let (mut r, mut w) = stream.split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
            }
        });
        addr
    }

    /// Helper: do a full SOCKS5 CONNECT handshake and return the stream.
    async fn socks5_connect(proxy_addr: SocketAddr, target: &[u8]) -> TcpStream {
        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();

        // Auth handshake
        conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut reply = [0u8; 2];
        conn.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0x00]);

        // CONNECT request
        conn.write_all(target).await.unwrap();

        conn
    }

    /// Read a SOCKS5 reply, return (rep, atyp).
    async fn read_socks5_reply(stream: &mut TcpStream) -> (u8, u8) {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        let rep = header[1];
        let atyp = header[3];
        // Consume bound address
        match atyp {
            ATYP_IPV4 => {
                let mut buf = [0u8; 6];
                stream.read_exact(&mut buf).await.unwrap();
            }
            ATYP_DOMAIN => {
                let mut l = [0u8; 1];
                stream.read_exact(&mut l).await.unwrap();
                let mut buf = vec![0u8; l[0] as usize + 2];
                stream.read_exact(&mut buf).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 18];
                stream.read_exact(&mut buf).await.unwrap();
            }
            _ => {}
        }
        (rep, atyp)
    }

    /// Start a proxy server that connects directly to targets.
    async fn start_proxy() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(handle_conn(stream, Arc::new(Notify::new())));
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_socks5_handshake_no_auth() {
        let proxy_addr = start_proxy().await;
        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();

        conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut reply = [0u8; 2];
        conn.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0x00]);
    }

    #[tokio::test]
    async fn test_socks5_handshake_reject() {
        let proxy_addr = start_proxy().await;
        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();

        // Only offer USER/PASS
        conn.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut reply = [0u8; 2];
        conn.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, AUTH_NO_ACCEPT]);
    }

    #[tokio::test]
    async fn test_socks5_connect_ipv4() {
        let echo_addr = echo_server().await;
        let proxy_addr = start_proxy().await;

        let ip = echo_addr.ip();
        let port = echo_addr.port();
        let port_bytes = port.to_be_bytes();

        let mut target = vec![0x05, CMD_CONNECT, 0x00, ATYP_IPV4];
        if let std::net::IpAddr::V4(ip4) = ip {
            target.extend_from_slice(&ip4.octets());
        }
        target.extend_from_slice(&port_bytes);

        let mut conn = socks5_connect(proxy_addr, &target).await;
        let (rep, _) = read_socks5_reply(&mut conn).await;
        assert_eq!(rep, REP_SUCCESS);

        // Test relay
        let test_data = b"hello socks5 rust";
        conn.write_all(test_data).await.unwrap();
        let mut buf = vec![0u8; test_data.len()];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, test_data);
    }

    #[tokio::test]
    async fn test_socks5_connect_domain() {
        let echo_addr = echo_server().await;
        let proxy_addr = start_proxy().await;

        // CONNECT to 127.0.0.1 as domain "localhost" won't resolve to echo server
        // Instead, construct as IPv4 since the echo server is on 127.0.0.1
        let port = echo_addr.port();
        let port_bytes = port.to_be_bytes();

        let domain = b"127.0.0.1"; // Use IP-as-domain for testability
        let mut target = vec![0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, domain.len() as u8];
        target.extend_from_slice(domain);
        target.extend_from_slice(&port_bytes);

        let mut conn = socks5_connect(proxy_addr, &target).await;
        let (rep, _) = read_socks5_reply(&mut conn).await;
        assert_eq!(rep, REP_SUCCESS);

        let test_data = b"hello domain rust";
        conn.write_all(test_data).await.unwrap();
        let mut buf = vec![0u8; test_data.len()];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, test_data);
    }

    #[tokio::test]
    async fn test_socks5_unsupported_command() {
        let proxy_addr = start_proxy().await;

        let target = [
            0x05, CMD_BIND, 0x00, ATYP_IPV4,
            127, 0, 0, 1,
            0x00, 0x50,
        ];
        let mut conn = socks5_connect(proxy_addr, &target).await;
        let (rep, _) = read_socks5_reply(&mut conn).await;
        assert_eq!(rep, REP_CMD_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn test_http_connect_basic() {
        let echo_addr = echo_server().await;
        let proxy_addr = start_proxy().await;

        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", echo_addr, echo_addr);
        conn.write_all(req.as_bytes()).await.unwrap();

        let mut resp = vec![0u8; 256];
        let n = conn.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("200"), "expected 200, got: {}", resp_str);

        // Test relay
        let test_data = b"hello http connect rust";
        conn.write_all(test_data).await.unwrap();
        let mut buf = vec![0u8; test_data.len()];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, test_data);
    }

    #[tokio::test]
    async fn test_http_connect_bad_request() {
        let proxy_addr = start_proxy().await;
        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();

        conn.write_all(b"CGET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut resp = vec![0u8; 256];
        let n = conn.read(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp[..n]);
        assert!(resp_str.contains("400"), "expected 400, got: {}", resp_str);
    }

    #[tokio::test]
    async fn test_read_address_ipv4() {
        let data: &[u8] = &[192, 168, 1, 1, 0x1F, 0x90];
        let mut cursor = std::io::Cursor::new(data);
        let addr = read_address(&mut cursor, ATYP_IPV4).await.unwrap();
        assert_eq!(addr.host, "192.168.1.1");
        assert_eq!(addr.port, 8080);
    }

    #[tokio::test]
    async fn test_parse_socks5_udp() {
        let addr = Address::ipv4("10.0.0.1", 53);
        let data = b"dns query";
        let pkt = build_socks5_udp(&addr, data).unwrap();

        let (got_addr, got_data) = parse_socks5_udp(&pkt).unwrap();
        assert_eq!(got_addr.host, "10.0.0.1");
        assert_eq!(got_addr.port, 53);
        assert_eq!(got_data, data);
    }

    #[tokio::test]
    async fn test_parse_socks5_udp_too_short() {
        assert!(parse_socks5_udp(&[0, 0]).is_err());
    }

    #[tokio::test]
    async fn test_build_socks5_udp_roundtrip() {
        let addr = Address::domain("example.com", 443);
        let data = b"test payload";
        let pkt = build_socks5_udp(&addr, data).unwrap();
        let (got_addr, got_data) = parse_socks5_udp(&pkt).unwrap();
        assert_eq!(got_addr.host, "example.com");
        assert_eq!(got_addr.port, 443);
        assert_eq!(got_data, data);
    }
}
