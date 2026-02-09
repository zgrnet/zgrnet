//! Full-stack smoke test for two Rust zgrnetd instances.
//!
//! Tests: ping, DNS, SOCKS5 proxy through KCP tunnel, throughput.
//!
//! Requires root/sudo:
//!   bazel build //rust:smoketest
//!   sudo bazel-bin/rust/smoketest

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{self, Command};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(feature = "tun")]
use {
    zgrnet::dns,
    zgrnet::host::{Config, Host, TunDevice},
    zgrnet::kcp::StreamIo,
    zgrnet::noise::{address, message::protocol, Key, KeyPair},
    zgrnet::tun,
};

fn main() {
    #[cfg(not(feature = "tun"))]
    {
        eprintln!("smoketest requires the 'tun' feature");
        process::exit(1);
    }
    #[cfg(feature = "tun")]
    run_test();
}

#[cfg(feature = "tun")]
struct RealTun {
    dev: tun::Device,
}

#[cfg(feature = "tun")]
impl TunDevice for RealTun {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.dev
            .read_packet(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.dev
            .write_packet(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }
    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "tun")]
fn run_test() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║     Rust zgrnetd Full-Stack Smoke Test                  ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    if unsafe { libc::getuid() } != 0 {
        eprintln!("requires root. Run with: sudo {}", std::env::args().next().unwrap());
        process::exit(1);
    }

    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut report = |name: &str, ok: bool| {
        if ok {
            passed += 1;
            println!("  ✅ PASS: {}", name);
        } else {
            failed += 1;
            println!("  ❌ FAIL: {}", name);
        }
    };

    // ── Generate Keys ────────────────────────────────────────────────
    step("Generating keypairs");
    let key_a = KeyPair::generate();
    let key_b = KeyPair::generate();
    info(&format!("A pubkey: {}", hex::encode(&key_a.public.0[..4])));
    info(&format!("B pubkey: {}", hex::encode(&key_b.public.0[..4])));

    // ── Create TUN Devices ───────────────────────────────────────────
    step("Creating TUN devices");
    tun::init().expect("init TUN");

    let tun_a = tun::Device::create(None).expect("create TUN A");
    let tun_b = tun::Device::create(None).expect("create TUN B");

    tun_a.set_mtu(1400).unwrap();
    tun_a.set_ipv4(Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(255, 255, 255, 0)).unwrap();
    tun_a.up().unwrap();
    info(&format!("TUN A: {} (100.64.0.1/24)", tun_a.name()));

    tun_b.set_mtu(1400).unwrap();
    tun_b.set_ipv4(Ipv4Addr::new(100, 64, 1, 1), Ipv4Addr::new(255, 255, 255, 0)).unwrap();
    tun_b.up().unwrap();
    info(&format!("TUN B: {} (100.64.1.1/24)", tun_b.name()));

    // ── Create Hosts ─────────────────────────────────────────────────
    step("Creating Hosts (TUN + encrypted UDP)");
    let host_a = Host::new(
        Config { private_key: key_a.clone(), tun_ipv4: Ipv4Addr::new(100, 64, 0, 1), mtu: 1400, listen_port: 0, peers: vec![] },
        Arc::new(RealTun { dev: tun_a }),
    ).expect("host A");

    let host_b = Host::new(
        Config { private_key: key_b.clone(), tun_ipv4: Ipv4Addr::new(100, 64, 1, 1), mtu: 1400, listen_port: 0, peers: vec![] },
        Arc::new(RealTun { dev: tun_b }),
    ).expect("host B");

    let port_a = host_a.local_addr().port();
    let port_b = host_b.local_addr().port();
    info(&format!("Host A: UDP :{}", port_a));
    info(&format!("Host B: UDP :{}", port_b));

    host_a.add_peer_with_ip(key_b.public, &format!("127.0.0.1:{}", port_b), Ipv4Addr::new(100, 64, 0, 2)).unwrap();
    host_b.add_peer_with_ip(key_a.public, &format!("127.0.0.1:{}", port_a), Ipv4Addr::new(100, 64, 1, 2)).unwrap();
    info("A knows B as 100.64.0.2");
    info("B knows A as 100.64.1.2");

    // ── Start Host forwarding ────────────────────────────────────────
    step("Starting Host forwarding loops");
    host_a.run();
    host_b.run();
    info("OK");

    // ── Noise Handshake ──────────────────────────────────────────────
    step("Noise IK handshake (A → B)");
    host_a.connect(&key_b.public).expect("handshake");
    info("Handshake complete!");
    thread::sleep(Duration::from_millis(200));

    // ── Start DNS Servers ────────────────────────────────────────────
    step("Starting Magic DNS servers");
    let dns_a = Arc::new(dns::Server::new(dns::server::ServerConfig {
        listen_addr: "127.0.0.1:0".into(),
        tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
        ..Default::default()
    }));
    let dns_a_socket = UdpSocket::bind("127.0.0.1:0").expect("bind DNS A");
    let dns_a_addr = dns_a_socket.local_addr().unwrap();
    let dns_a2 = dns_a.clone();
    thread::spawn(move || dns_loop(dns_a2, dns_a_socket));
    info(&format!("DNS A: {}", dns_a_addr));

    let dns_b = Arc::new(dns::Server::new(dns::server::ServerConfig {
        listen_addr: "127.0.0.1:0".into(),
        tun_ipv4: Ipv4Addr::new(100, 64, 1, 1),
        ..Default::default()
    }));
    let dns_b_socket = UdpSocket::bind("127.0.0.1:0").expect("bind DNS B");
    let dns_b_addr = dns_b_socket.local_addr().unwrap();
    let dns_b2 = dns_b.clone();
    thread::spawn(move || dns_loop(dns_b2, dns_b_socket));
    info(&format!("DNS B: {}", dns_b_addr));

    // ── Start Proxy + TCP_PROXY accept ───────────────────────────────
    step("Starting SOCKS5 proxy + TCP_PROXY accept loops");

    let udp_a = host_a.udp().clone();
    let udp_b = host_b.udp().clone();

    // Proxy A → tunnel → B
    let proxy_a_ln = TcpListener::bind("127.0.0.1:0").expect("bind proxy A");
    let proxy_a_addr = proxy_a_ln.local_addr().unwrap();
    let pk_b = key_b.public;
    let udp_a2 = udp_a.clone();
    thread::spawn(move || proxy_loop(proxy_a_ln, udp_a2, pk_b));

    // B accepts TCP_PROXY streams
    let pk_a = key_a.public;
    let udp_b2 = udp_b.clone();
    thread::spawn(move || tcp_proxy_accept_loop(udp_b2, pk_a));

    // Proxy B → tunnel → A
    let proxy_b_ln = TcpListener::bind("127.0.0.1:0").expect("bind proxy B");
    let proxy_b_addr = proxy_b_ln.local_addr().unwrap();
    let udp_b3 = udp_b.clone();
    thread::spawn(move || proxy_loop(proxy_b_ln, udp_b3, pk_a));

    // A accepts TCP_PROXY streams
    let udp_a3 = udp_a.clone();
    thread::spawn(move || tcp_proxy_accept_loop(udp_a3, pk_b));

    info(&format!("Proxy A (→ tunnel → B): {}", proxy_a_addr));
    info(&format!("Proxy B (→ tunnel → A): {}", proxy_b_addr));

    thread::sleep(Duration::from_millis(100));

    // ══════════════════════════════════════════════════════════════════
    //  TESTS
    // ══════════════════════════════════════════════════════════════════
    println!();
    println!("── Tests ──────────────────────────────────────────────────");

    println!();
    println!("[Test 1] Ping A→B (100.64.0.2) via encrypted tunnel");
    report("Ping A→B", run_ping("100.64.0.2"));

    println!();
    println!("[Test 2] Ping B→A (100.64.1.2) via encrypted tunnel");
    report("Ping B→A", run_ping("100.64.1.2"));

    println!();
    println!("[Test 3] DNS: localhost.zigor.net → TUN A IP");
    report("DNS A", test_dns(dns_a_addr, "localhost.zigor.net", "100.64.0.1"));

    println!();
    println!("[Test 4] DNS: localhost.zigor.net → TUN B IP");
    report("DNS B", test_dns(dns_b_addr, "localhost.zigor.net", "100.64.1.1"));

    println!();
    println!("[Test 5] SOCKS5 Proxy: A → KCP tunnel → B → HTTP target");
    report("Proxy A→B", test_socks5_proxy(proxy_a_addr));

    println!();
    println!("[Test 6] SOCKS5 Proxy: B → KCP tunnel → A → HTTP target");
    report("Proxy B→A", test_socks5_proxy(proxy_b_addr));

    println!();
    println!("[Test 7] Throughput: A → KCP tunnel → B (32 MB)");
    report("Throughput A→B", test_throughput(proxy_a_addr, 32 * 1024 * 1024));

    // ── Summary ──────────────────────────────────────────────────────
    println!();
    println!("══════════════════════════════════════════════════════════");
    println!("  Results: {} passed, {} failed (total {})", passed, failed, passed + failed);
    println!("══════════════════════════════════════════════════════════");
    println!();

    if failed > 0 {
        println!("SOME TESTS FAILED");
        process::exit(1);
    }
    println!("ALL TESTS PASSED!");
    process::exit(0);
}

// ============================================================================
// DNS server loop
// ============================================================================

#[cfg(feature = "tun")]
fn dns_loop(server: Arc<dns::Server>, socket: UdpSocket) {
    let mut buf = [0u8; 4096];
    loop {
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(_) => return,
        };
        if let Ok(resp) = server.handle_query(&buf[..n]) {
            let _ = socket.send_to(&resp, from);
        }
    }
}

// ============================================================================
// SOCKS5 proxy loop (tunnels through KCP)
// ============================================================================

#[cfg(feature = "tun")]
fn proxy_loop(listener: TcpListener, udp: Arc<zgrnet::net::UDP>, target_pk: Key) {
    for stream in listener.incoming() {
        let stream = match stream { Ok(s) => s, Err(_) => continue };
        let udp = udp.clone();
        thread::spawn(move || {
            handle_socks5(stream, &udp, &target_pk);
        });
    }
}

#[cfg(feature = "tun")]
fn handle_socks5(mut conn: TcpStream, udp: &Arc<zgrnet::net::UDP>, target_pk: &Key) {
    let mut buf = [0u8; 258];
    // Auth
    if conn.read_exact(&mut buf[..2]).is_err() { return; }
    if buf[0] != 0x05 { return; }
    let n = buf[1] as usize;
    if conn.read_exact(&mut buf[..n]).is_err() { return; }
    if conn.write_all(&[0x05, 0x00]).is_err() { return; }

    // CONNECT request
    if conn.read_exact(&mut buf[..4]).is_err() { return; }
    if buf[1] != 0x01 { return; } // CMD_CONNECT only
    let atyp = buf[3];

    let addr = match atyp {
        0x01 => { // IPv4
            let mut b = [0u8; 6];
            if conn.read_exact(&mut b).is_err() { return; }
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            address::Address { atyp: address::ATYP_IPV4, host: ip.to_string(), port }
        }
        0x03 => { // Domain
            let mut lb = [0u8; 1];
            if conn.read_exact(&mut lb).is_err() { return; }
            let mut b = vec![0u8; lb[0] as usize + 2];
            if conn.read_exact(&mut b).is_err() { return; }
            let len = lb[0] as usize;
            let host = String::from_utf8_lossy(&b[..len]).to_string();
            let port = u16::from_be_bytes([b[len], b[len + 1]]);
            address::Address { atyp: address::ATYP_DOMAIN, host, port }
        }
        _ => return,
    };

    // Open KCP stream
    let metadata = match addr.encode() { Ok(m) => m, Err(_) => return };
    let stream = match udp.open_stream(target_pk, protocol::TCP_PROXY, &metadata) {
        Ok(s) => s,
        Err(_) => { let _ = conn.write_all(&[0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0]); return; }
    };

    // Success reply
    let _ = conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]);

    // Relay
    let mut sio = StreamIo(stream);
    let mut conn2 = conn.try_clone().unwrap();
    let kcp_stream = sio.0.clone();
    let t = thread::spawn(move || {
        let mut kcp_w = StreamIo(kcp_stream);
        let _ = io::copy(&mut conn2, &mut kcp_w);
    });
    let _ = io::copy(&mut sio, &mut conn);
    let _ = t.join();
}

// ============================================================================
// TCP_PROXY accept loop (exit node)
// ============================================================================

#[cfg(feature = "tun")]
fn tcp_proxy_accept_loop(udp: Arc<zgrnet::net::UDP>, peer_pk: Key) {
    loop {
        let stream = match udp.accept_stream(&peer_pk) {
            Ok(s) => s,
            Err(_) => return,
        };
        if stream.proto() != protocol::TCP_PROXY {
            stream.shutdown();
            continue;
        }
        let metadata = stream.metadata().to_vec();
        thread::spawn(move || {
            let mut sio = StreamIo(stream);
            if let Ok((addr, _)) = address::Address::decode(&metadata) {
                let target = format!("{}:{}", addr.host, addr.port);
                if let Ok(mut remote) = TcpStream::connect_timeout(
                    &target.parse::<SocketAddr>().unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap()),
                    Duration::from_secs(5),
                ) {
                    let mut remote2 = remote.try_clone().unwrap();
                    let kcp = sio.0.clone();
                    let t = thread::spawn(move || {
                        let mut kcp_w = StreamIo(kcp);
                        let _ = io::copy(&mut remote2, &mut kcp_w);
                    });
                    let _ = io::copy(&mut sio, &mut remote);
                    let _ = t.join();
                }
            }
        });
    }
}

// ============================================================================
// Test helpers
// ============================================================================

fn run_ping(target: &str) -> bool {
    let out = Command::new("ping").args(["-c", "3", "-W", "2", target]).output();
    match out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.trim().lines() { println!("    {}", line); }
            o.status.success() && (s.contains("0.0% packet loss") || s.contains(" 0% packet loss"))
        }
        Err(e) => { println!("    error: {}", e); false }
    }
}

fn test_dns(server_addr: SocketAddr, domain: &str, expected_ip: &str) -> bool {
    let sock = match UdpSocket::bind("0.0.0.0:0") { Ok(s) => s, Err(e) => { println!("    bind: {}", e); return false; } };
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok();

    let query = build_dns_query(domain);
    if sock.send_to(&query, server_addr).is_err() { println!("    send failed"); return false; }

    let mut buf = [0u8; 4096];
    let n = match sock.recv(&mut buf) { Ok(n) => n, Err(e) => { println!("    recv: {}", e); return false; } };

    if let Some(ip) = parse_dns_response_ip(&buf[..n]) {
        println!("    {} → {}", domain, ip);
        ip == expected_ip
    } else {
        println!("    no answer"); false
    }
}

fn test_socks5_proxy(proxy_addr: SocketAddr) -> bool {
    // Start HTTP server
    let http_ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = http_ln.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in http_ln.incoming() {
            let mut s = stream.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let body = "zgrnet-ok";
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            let _ = s.write_all(resp.as_bytes());
        }
    });

    let target = format!("127.0.0.1:{}", http_port);
    println!("    HTTP server: http://{}/", target);
    println!("    via proxy:   {}", proxy_addr);

    let mut conn = match TcpStream::connect_timeout(&proxy_addr, Duration::from_secs(3)) {
        Ok(c) => c, Err(e) => { println!("    connect: {}", e); return false; }
    };

    // SOCKS5 handshake
    conn.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut resp = [0u8; 2];
    conn.read_exact(&mut resp).unwrap();

    let ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip.octets());
    req.push((http_port >> 8) as u8);
    req.push(http_port as u8);
    conn.write_all(&req).unwrap();

    let mut reply = [0u8; 10];
    conn.read_exact(&mut reply).unwrap();
    if reply[1] != 0x00 { println!("    connect failed: 0x{:02x}", reply[1]); return false; }

    // HTTP GET
    let http_req = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", target);
    conn.write_all(http_req.as_bytes()).unwrap();

    conn.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let mut body = String::new();
    let _ = conn.read_to_string(&mut body);
    println!("    response: {}", body.lines().next().unwrap_or(""));

    body.contains("zgrnet-ok")
}

#[cfg(feature = "tun")]
fn test_throughput(proxy_addr: SocketAddr, size: usize) -> bool {
    // HTTP server streaming `size` bytes
    let http_ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_port = http_ln.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in http_ln.incoming() {
            let mut s = stream.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf); // read HTTP request
            let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", size);
            let _ = s.write_all(header.as_bytes());
            let chunk = vec![0x42u8; 64 * 1024];
            let mut remaining = size;
            while remaining > 0 {
                let n = std::cmp::min(chunk.len(), remaining);
                if s.write_all(&chunk[..n]).is_err() { break; }
                remaining -= n;
            }
        }
    });

    println!("    server: 127.0.0.1:{} ({} MB)", http_port, size / (1024 * 1024));
    println!("    proxy:  {}", proxy_addr);

    let mut conn = match TcpStream::connect_timeout(&proxy_addr, Duration::from_secs(5)) {
        Ok(c) => c, Err(e) => { println!("    connect: {}", e); return false; }
    };

    // SOCKS5 handshake
    conn.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut resp = [0u8; 2];
    conn.read_exact(&mut resp).unwrap();

    let ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip.octets());
    req.push((http_port >> 8) as u8);
    req.push(http_port as u8);
    conn.write_all(&req).unwrap();

    let mut reply = [0u8; 10];
    conn.read_exact(&mut reply).unwrap();
    if reply[1] != 0x00 { println!("    socks5 failed"); return false; }

    // HTTP GET
    let http_req = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", http_port);
    conn.write_all(http_req.as_bytes()).unwrap();

    let start = Instant::now();
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0usize;
    loop {
        conn.set_read_timeout(Some(Duration::from_secs(30))).ok();
        match conn.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => { total += n; if total >= size { break; } }
            Err(_) => break,
        }
    }
    let elapsed = start.elapsed();

    let data = if total > 200 { total - 200 } else { total };
    let mbps = data as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!("    downloaded: {} bytes in {:?}", total, elapsed);
    println!("    throughput: {:.1} MB/s", mbps);

    data >= size * 9 / 10
}

// ============================================================================
// DNS helpers
// ============================================================================

fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(&[0x12, 0x34]); // ID
    buf.extend_from_slice(&[0x01, 0x00]); // Flags: RD
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR

    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00);
    buf.extend_from_slice(&[0x00, 0x01]); // Type A
    buf.extend_from_slice(&[0x00, 0x01]); // Class IN
    buf
}

fn parse_dns_response_ip(data: &[u8]) -> Option<String> {
    if data.len() < 12 { return None; }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 { return None; }

    // Skip header + question
    let mut off = 12;
    while off < data.len() {
        let l = data[off] as usize;
        if l == 0 { off += 1; break; }
        if l >= 192 { off += 2; break; }
        off += 1 + l;
    }
    off += 4; // QTYPE + QCLASS

    // Parse first answer
    if off >= data.len() { return None; }
    if data[off] >= 192 { off += 2; } else {
        while off < data.len() {
            let l = data[off] as usize;
            if l == 0 { off += 1; break; }
            off += 1 + l;
        }
    }
    if off + 10 > data.len() { return None; }
    let rdlen = u16::from_be_bytes([data[off + 8], data[off + 9]]) as usize;
    off += 10;
    if off + rdlen > data.len() || rdlen != 4 { return None; }

    Some(format!("{}.{}.{}.{}", data[off], data[off + 1], data[off + 2], data[off + 3]))
}

fn step(msg: &str) { println!("\n── {} ──", msg); }
fn info(msg: &str) { println!("  {}", msg); }
