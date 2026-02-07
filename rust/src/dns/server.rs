//! Magic DNS server with zigor.net resolution and upstream forwarding.

use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket, SocketAddr};
use std::sync::{Arc, Mutex};

use super::protocol::*;
use super::fakeip::FakeIPPool;

/// Default TTL for Magic DNS responses (60 seconds).
pub const DEFAULT_TTL: u32 = 60;
/// Default upstream DNS server.
pub const DEFAULT_UPSTREAM: &str = "8.8.8.8:53";
/// The zigor.net domain suffix.
pub const ZIGOR_NET_SUFFIX: &str = ".zigor.net";

/// IPAllocator trait for pubkey -> IP mapping.
pub trait IPAllocator: Send + Sync {
    fn lookup_by_pubkey(&self, pubkey: &[u8; 32]) -> Option<Ipv4Addr>;
    fn lookup_by_ip(&self, ip: Ipv4Addr) -> Option<[u8; 32]>;
}

/// Server configuration.
pub struct ServerConfig {
    pub listen_addr: String,
    pub tun_ipv4: Ipv4Addr,
    pub tun_ipv6: Option<Ipv6Addr>,
    pub upstream: String,
    pub ip_alloc: Option<Arc<dyn IPAllocator>>,
    pub fake_pool: Option<Arc<Mutex<FakeIPPool>>>,
    pub match_domains: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen_addr: "127.0.0.1:5353".to_string(),
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            tun_ipv6: None,
            upstream: DEFAULT_UPSTREAM.to_string(),
            ip_alloc: None,
            fake_pool: None,
            match_domains: Vec::new(),
        }
    }
}

/// Magic DNS server.
pub struct Server {
    config: ServerConfig,
    /// Persistent upstream UDP socket for connection reuse.
    upstream_socket: Option<UdpSocket>,
}

impl Server {
    /// Create a new DNS server.
    pub fn new(config: ServerConfig) -> Self {
        // Eagerly initialize upstream connection for performance.
        let upstream_socket = config.upstream.parse::<SocketAddr>().ok().and_then(|addr| {
            let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
            socket.connect(addr).ok()?;
            socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok()?;
            Some(socket)
        });
        Server { config, upstream_socket }
    }

    /// Handle a DNS query and return the response bytes.
    pub fn handle_query(&self, query_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let msg = Message::decode(query_data)?;

        if msg.questions.is_empty() {
            let resp = Message::new_response(&msg, RCODE_FORMERR);
            return Ok(resp.encode()?);
        }

        let q = &msg.questions[0];
        let name = q.name.to_lowercase();

        // Try zigor.net resolution
        if name.ends_with(ZIGOR_NET_SUFFIX) || name == "zigor.net" {
            return self.resolve_zigor_net(&msg, &name, q.qtype);
        }

        // Try Fake IP matching
        if self.config.fake_pool.is_some() && self.matches_domain(&name) {
            return self.resolve_fake_ip(&msg, &name, q.qtype);
        }

        // Forward to upstream
        self.forward_upstream(query_data)
    }

    fn resolve_zigor_net(
        &self,
        query: &Message,
        name: &str,
        qtype: u16,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let subdomain = if name == "zigor.net" {
            ""
        } else {
            name.trim_end_matches(ZIGOR_NET_SUFFIX)
        };

        // localhost.zigor.net -> TUN IP
        if subdomain == "localhost" {
            return self.respond_with_tun_ip(query, name, qtype);
        }

        // Split pubkey: {first32hex}.{last32hex}.zigor.net
        // Pubkey is split into two 32-char labels to comply with RFC 1035 (max 63 chars/label).
        if let Some(dot_pos) = subdomain.find('.') {
            let first = &subdomain[..dot_pos];
            let rest = &subdomain[dot_pos + 1..];
            if first.len() + rest.len() == 64 && is_hex_string(first) && is_hex_string(rest) {
                let combined = format!("{}{}", first, rest);
                return self.respond_with_peer_ip(query, name, &combined, qtype);
            }
        }

        // Unknown *.zigor.net
        let resp = Message::new_response(query, RCODE_NXDOMAIN);
        Ok(resp.encode()?)
    }

    fn respond_with_tun_ip(
        &self,
        query: &Message,
        name: &str,
        qtype: u16,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut resp = Message::new_response(query, RCODE_NOERROR);

        match qtype {
            TYPE_A => {
                let octets = self.config.tun_ipv4.octets();
                resp.answers.push(new_a_record(name, DEFAULT_TTL, octets));
            }
            TYPE_AAAA => {
                if let Some(ipv6) = self.config.tun_ipv6 {
                    resp.answers
                        .push(new_aaaa_record(name, DEFAULT_TTL, ipv6.octets()));
                }
            }
            _ => {}
        }

        Ok(resp.encode()?)
    }

    fn respond_with_peer_ip(
        &self,
        query: &Message,
        name: &str,
        hex_pubkey: &str,
        qtype: u16,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let alloc = match &self.config.ip_alloc {
            Some(a) => a,
            None => {
                let resp = Message::new_response(query, RCODE_SERVFAIL);
                return Ok(resp.encode()?);
            }
        };

        let pubkey_bytes = match hex::decode(hex_pubkey) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                let resp = Message::new_response(query, RCODE_NXDOMAIN);
                return Ok(resp.encode()?);
            }
        };

        match alloc.lookup_by_pubkey(&pubkey_bytes) {
            Some(ip) => {
                let mut resp = Message::new_response(query, RCODE_NOERROR);
                if qtype == TYPE_A {
                    resp.answers.push(new_a_record(name, DEFAULT_TTL, ip.octets()));
                }
                Ok(resp.encode()?)
            }
            None => {
                let resp = Message::new_response(query, RCODE_NXDOMAIN);
                Ok(resp.encode()?)
            }
        }
    }

    fn resolve_fake_ip(
        &self,
        query: &Message,
        name: &str,
        qtype: u16,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if qtype != TYPE_A {
            let resp = Message::new_response(query, RCODE_NOERROR);
            return Ok(resp.encode()?);
        }

        let pool = self.config.fake_pool.as_ref().unwrap();
        let ip = pool.lock().unwrap().assign(name);
        let mut resp = Message::new_response(query, RCODE_NOERROR);
        resp.answers.push(new_a_record(name, DEFAULT_TTL, ip.octets()));
        Ok(resp.encode()?)
    }

    /// Forward a DNS query to the upstream resolver.
    /// Uses a persistent UDP socket for performance. Falls back to
    /// a per-query socket if the persistent one is unavailable.
    fn forward_upstream(
        &self,
        query_data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if let Some(ref socket) = self.upstream_socket {
            socket.send(query_data)?;
            let mut buf = vec![0u8; 4096];
            let n = socket.recv(&mut buf)?;
            buf.truncate(n);
            return Ok(buf);
        }

        // Fallback: one-off connection
        let upstream: SocketAddr = self.config.upstream.parse()?;
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        socket.send_to(query_data, upstream)?;

        let mut buf = vec![0u8; 4096];
        let (n, _) = socket.recv_from(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn matches_domain(&self, name: &str) -> bool {
        self.config.match_domains.iter().any(|suffix| name.ends_with(suffix.as_str()))
    }
}

fn is_hex_string(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAllocator {
        map: std::collections::HashMap<[u8; 32], Ipv4Addr>,
    }

    impl MockAllocator {
        fn new() -> Self {
            MockAllocator { map: std::collections::HashMap::new() }
        }
        fn add(&mut self, pubkey: [u8; 32], ip: Ipv4Addr) {
            self.map.insert(pubkey, ip);
        }
    }

    impl IPAllocator for MockAllocator {
        fn lookup_by_pubkey(&self, pubkey: &[u8; 32]) -> Option<Ipv4Addr> {
            self.map.get(pubkey).copied()
        }
        fn lookup_by_ip(&self, _ip: Ipv4Addr) -> Option<[u8; 32]> {
            None
        }
    }

    fn build_query(name: &str, qtype: u16) -> Vec<u8> {
        let msg = Message {
            header: Header {
                id: 0x1234, flags: FLAG_RD,
                qd_count: 1, an_count: 0, ns_count: 0, ar_count: 0,
            },
            questions: vec![Question {
                name: name.to_string(), qtype, qclass: CLASS_IN,
            }],
            answers: vec![], authorities: vec![], additionals: vec![],
        };
        msg.encode().unwrap()
    }

    #[test]
    fn test_localhost_zigor_net() {
        let srv = Server::new(ServerConfig {
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            ..Default::default()
        });

        let query = build_query("localhost.zigor.net", TYPE_A);
        let resp_data = srv.handle_query(&query).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.header.rcode(), RCODE_NOERROR);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].rdata, vec![100, 64, 0, 1]);
    }

    #[test]
    fn test_localhost_aaaa() {
        let srv = Server::new(ServerConfig {
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            tun_ipv6: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            ..Default::default()
        });

        let query = build_query("localhost.zigor.net", TYPE_AAAA);
        let resp_data = srv.handle_query(&query).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].rtype, TYPE_AAAA);
        assert_eq!(resp.answers[0].rdata.len(), 16);
    }

    #[test]
    fn test_case_insensitive() {
        let srv = Server::new(ServerConfig {
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            ..Default::default()
        });

        let query = build_query("LOCALHOST.ZIGOR.NET", TYPE_A);
        let resp_data = srv.handle_query(&query).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.header.rcode(), RCODE_NOERROR);
        assert_eq!(resp.answers.len(), 1);
    }

    #[test]
    fn test_pubkey_zigor_net() {
        let mut alloc = MockAllocator::new();
        let mut pubkey = [0u8; 32];
        for (i, b) in pubkey.iter_mut().enumerate() {
            *b = i as u8;
        }
        alloc.add(pubkey, Ipv4Addr::new(100, 64, 0, 42));

        let srv = Server::new(ServerConfig {
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            ip_alloc: Some(Arc::new(alloc)),
            ..Default::default()
        });

        let hex_pk = hex::encode(pubkey);
        let split_name = format!("{}.{}.zigor.net", &hex_pk[..32], &hex_pk[32..]);
        let query = build_query(&split_name, TYPE_A);
        let resp_data = srv.handle_query(&query).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.header.rcode(), RCODE_NOERROR);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].rdata, vec![100, 64, 0, 42]);
    }

    #[test]
    fn test_pubkey_not_found() {
        let alloc = MockAllocator::new();
        let srv = Server::new(ServerConfig {
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            ip_alloc: Some(Arc::new(alloc)),
            ..Default::default()
        });

        let hex_pk = "00".repeat(32);
        let split_name = format!("{}.{}.zigor.net", &hex_pk[..32], &hex_pk[32..]);
        let query = build_query(&split_name, TYPE_A);
        let resp_data = srv.handle_query(&query).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.header.rcode(), RCODE_NXDOMAIN);
    }

    #[test]
    fn test_unknown_subdomain() {
        let srv = Server::new(ServerConfig {
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            ..Default::default()
        });

        let query = build_query("unknown.zigor.net", TYPE_A);
        let resp_data = srv.handle_query(&query).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.header.rcode(), RCODE_NXDOMAIN);
    }

    #[test]
    fn test_no_allocator() {
        let srv = Server::new(ServerConfig {
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            ..Default::default()
        });

        let hex_pk = "01".repeat(32);
        let split_name = format!("{}.{}.zigor.net", &hex_pk[..32], &hex_pk[32..]);
        let query = build_query(&split_name, TYPE_A);
        let resp_data = srv.handle_query(&query).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.header.rcode(), RCODE_SERVFAIL);
    }

    #[test]
    fn test_fake_ip() {
        let pool = Arc::new(Mutex::new(FakeIPPool::new(100)));
        let srv = Server::new(ServerConfig {
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            fake_pool: Some(pool),
            match_domains: vec![".example.com".to_string()],
            ..Default::default()
        });

        let query = build_query("test.example.com", TYPE_A);
        let resp_data = srv.handle_query(&query).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.header.rcode(), RCODE_NOERROR);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].rdata[0], 198);
        assert_eq!(resp.answers[0].rdata[1], 18);

        // Same domain, same IP
        let resp_data2 = srv.handle_query(&query).unwrap();
        let resp2 = Message::decode(&resp_data2).unwrap();
        assert_eq!(resp.answers[0].rdata, resp2.answers[0].rdata);
    }

    #[test]
    fn test_empty_query() {
        let srv = Server::new(ServerConfig::default());

        let msg = Message {
            header: Header {
                id: 0x1234, flags: FLAG_RD,
                qd_count: 0, an_count: 0, ns_count: 0, ar_count: 0,
            },
            questions: vec![], answers: vec![], authorities: vec![], additionals: vec![],
        };
        let data = msg.encode().unwrap();
        let resp_data = srv.handle_query(&data).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.header.rcode(), RCODE_FORMERR);
    }

    #[test]
    fn test_is_hex_string() {
        assert!(is_hex_string("0123456789abcdef"));
        assert!(is_hex_string("ABCDEF"));
        assert!(!is_hex_string(""));
        assert!(!is_hex_string("0123g"));
    }

    #[test]
    fn test_upstream_forwarding() {
        // Start a fake upstream DNS server
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let upstream_clone = upstream.try_clone().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let (n, remote) = upstream_clone.recv_from(&mut buf).unwrap();
            let msg = Message::decode(&buf[..n]).unwrap();
            let mut resp = Message::new_response(&msg, RCODE_NOERROR);
            resp.answers.push(new_a_record(&msg.questions[0].name, 300, [93, 184, 216, 34]));
            let data = resp.encode().unwrap();
            upstream_clone.send_to(&data, remote).unwrap();
        });

        let srv = Server::new(ServerConfig {
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            upstream: upstream_addr.to_string(),
            ..Default::default()
        });

        let query = build_query("example.com", TYPE_A);
        let resp_data = srv.handle_query(&query).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.header.rcode(), RCODE_NOERROR);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].rdata, vec![93, 184, 216, 34]);
    }

    #[test]
    fn test_malformed_query() {
        let srv = Server::new(ServerConfig::default());
        assert!(srv.handle_query(&[0x00, 0x01]).is_err());
    }

    #[test]
    fn test_localhost_no_ipv6() {
        let srv = Server::new(ServerConfig {
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            tun_ipv6: None,
            ..Default::default()
        });

        let query = build_query("localhost.zigor.net", TYPE_AAAA);
        let resp_data = srv.handle_query(&query).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.header.rcode(), RCODE_NOERROR);
        assert_eq!(resp.answers.len(), 0); // No IPv6 configured
    }

    #[test]
    fn test_fake_ip_aaaa() {
        let pool = Arc::new(Mutex::new(FakeIPPool::new(100)));
        let srv = Server::new(ServerConfig {
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            fake_pool: Some(pool),
            match_domains: vec![".example.com".to_string()],
            ..Default::default()
        });

        let query = build_query("test.example.com", TYPE_AAAA);
        let resp_data = srv.handle_query(&query).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.header.rcode(), RCODE_NOERROR);
        assert_eq!(resp.answers.len(), 0); // No AAAA for fake IP
    }

    #[test]
    fn test_pubkey_aaaa() {
        let mut alloc = MockAllocator::new();
        let mut pubkey = [0u8; 32];
        for (i, b) in pubkey.iter_mut().enumerate() {
            *b = i as u8;
        }
        alloc.add(pubkey, Ipv4Addr::new(100, 64, 0, 42));

        let srv = Server::new(ServerConfig {
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            ip_alloc: Some(Arc::new(alloc)),
            ..Default::default()
        });

        let hex_pk = hex::encode(pubkey);
        let split_name = format!("{}.{}.zigor.net", &hex_pk[..32], &hex_pk[32..]);
        let query = build_query(&split_name, TYPE_AAAA);
        let resp_data = srv.handle_query(&query).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.header.rcode(), RCODE_NOERROR);
        assert_eq!(resp.answers.len(), 0); // No AAAA for peer
    }

    #[test]
    fn test_bare_zigor_net() {
        let srv = Server::new(ServerConfig {
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            ..Default::default()
        });

        let query = build_query("zigor.net", TYPE_A);
        let resp_data = srv.handle_query(&query).unwrap();
        let resp = Message::decode(&resp_data).unwrap();

        assert_eq!(resp.header.rcode(), RCODE_NXDOMAIN);
    }

    #[test]
    fn test_authorities_additionals_roundtrip() {
        let msg = Message {
            header: Header {
                id: 0x5555, flags: FLAG_QR | FLAG_AA,
                qd_count: 1, an_count: 1, ns_count: 1, ar_count: 1,
            },
            questions: vec![Question {
                name: "example.com".to_string(), qtype: TYPE_A, qclass: CLASS_IN,
            }],
            answers: vec![new_a_record("example.com", 60, [1, 2, 3, 4])],
            authorities: vec![ResourceRecord {
                name: "example.com".to_string(), rtype: 2, rclass: CLASS_IN,
                ttl: 3600, rdata: encode_name("ns1.example.com").unwrap(),
            }],
            additionals: vec![new_a_record("ns1.example.com", 3600, [5, 6, 7, 8])],
        };

        let encoded = msg.encode().unwrap();
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(decoded.answers.len(), 1);
        assert_eq!(decoded.authorities.len(), 1);
        assert_eq!(decoded.additionals.len(), 1);
        assert_eq!(decoded.additionals[0].name, "ns1.example.com");
    }

    #[test]
    fn test_header_opcode_rcode() {
        let h = Header { id: 0, flags: 0, qd_count: 0, an_count: 0, ns_count: 0, ar_count: 0 };
        assert!(!h.is_response());
        assert_eq!(h.rcode(), 0);

        let h2 = Header { id: 0, flags: FLAG_QR | RCODE_NXDOMAIN, qd_count: 0, an_count: 0, ns_count: 0, ar_count: 0 };
        assert!(h2.is_response());
        assert_eq!(h2.rcode(), RCODE_NXDOMAIN);
    }
}
