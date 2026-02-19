//! zgrnetd — the zgrnet daemon (Rust implementation).
//!
//! Loads a config file and starts:
//! - TUN device with a CGNAT IP
//! - Noise Protocol encrypted UDP transport
//! - Host (bridges TUN ↔ UDP, routes IP packets to/from peers)
//! - Magic DNS server (resolves *.zigor.net → TUN IPs)
//! - SOCKS5/HTTP CONNECT proxy server
//!
//! Usage:
//!   zgrnetd -c /path/to/config.yaml

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use zgrnet::api;
use zgrnet::config;
use zgrnet::dns;
use zgrnet::host::{self, Host, TunDevice};
use zgrnet::kcp::StreamIo;
use zgrnet::listener;
use zgrnet::noise::address;
use zgrnet::noise::message::protocol;
use zgrnet::noise::{Key, KeyPair};

#[cfg(feature = "dnsmgr")]
use zgrnet::dnsmgr;

#[cfg(feature = "tun")]
use zgrnet::tun;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config_path = parse_args(&args);

    if let Err(e) = run(&config_path) {
        eprintln!("fatal: {}", e);
        std::process::exit(1);
    }
}

fn parse_args(args: &[String]) -> String {
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-c" && i + 1 < args.len() {
            return args[i + 1].clone();
        }
        i += 1;
    }
    eprintln!("Usage: zgrnetd -c <config.yaml>");
    std::process::exit(1);
}

fn run(cfg_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("loading config: {}", cfg_path);

    // ── 1. Load and validate config ──────────────────────────────────
    let cfg = config::load(cfg_path)?;

    let tun_mtu = if cfg.net.tun_mtu == 0 { 1400 } else { cfg.net.tun_mtu };
    let listen_port = if cfg.net.listen_port == 0 { 51820 } else { cfg.net.listen_port };
    let private_key_path = if cfg.net.private_key.is_empty() {
        "private.key".to_string()
    } else {
        cfg.net.private_key.clone()
    };

    // ── 2. Load or generate private key ──────────────────────────────
    let key_pair = load_or_generate_key(&private_key_path)?;
    eprintln!("public key: {}", hex::encode(key_pair.public));

    // ── 3. Create data directory ─────────────────────────────────────
    let data_dir = Path::new(cfg_path)
        .parent()
        .unwrap_or(Path::new("."))
        .join("data");
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("create data dir {:?}: {}", data_dir, e))?;

    // ── 4. Create and configure TUN device ───────────────────────────
    #[cfg(feature = "tun")]
    let (tun_dev, tun_name) = {
        eprintln!("creating TUN device...");
        let dev = tun::Device::create(None)
            .map_err(|e| format!("create TUN: {}", e))?;
        dev.set_mtu(tun_mtu as i32)
            .map_err(|e| format!("set TUN MTU: {}", e))?;

        let tun_ip: Ipv4Addr = cfg.net.tun_ipv4.parse()
            .map_err(|_| format!("invalid TUN IP: {}", cfg.net.tun_ipv4))?;
        // /10 netmask for CGNAT range
        let netmask = Ipv4Addr::new(255, 192, 0, 0);
        dev.set_ipv4(tun_ip, netmask)
            .map_err(|e| format!("set TUN IPv4: {}", e))?;
        dev.up()
            .map_err(|e| format!("bring TUN up: {}", e))?;

        let name = dev.name().to_string();
        eprintln!("TUN {}: {}/10, MTU {}", name, tun_ip, tun_mtu);

        // Fix macOS utun routing.
        // macOS utun is point-to-point: the kernel only creates a host route
        // for the peer address, ignoring the /10 subnet mask. We add:
        //   1. Host route: TUN_IP → lo0 (local TCP connections)
        //   2. Subnet route: 100.64.0.0/10 → utun (peer traffic)
        if cfg!(target_os = "macos") {
            // 1. Host route for local IP
            match std::process::Command::new("/sbin/route")
                .args(["add", "-host", &tun_ip.to_string(), "-interface", "lo0"])
                .output()
            {
                Ok(out) if out.status.success() => {
                    eprintln!("route: {} → lo0 (local)", tun_ip);
                }
                Ok(out) => {
                    eprintln!("warning: host route {}: {}",
                        tun_ip, String::from_utf8_lossy(&out.stderr).trim());
                }
                Err(e) => eprintln!("warning: host route {}: {}", tun_ip, e),
            }
            // 2. Subnet route for CGNAT range
            match std::process::Command::new("/sbin/route")
                .args(["add", "-net", "100.64.0.0/10", "-interface", &name])
                .output()
            {
                Ok(out) if out.status.success() => {
                    eprintln!("route: 100.64.0.0/10 → {} (peers)", name);
                }
                Ok(out) => {
                    eprintln!("warning: subnet route: {}",
                        String::from_utf8_lossy(&out.stderr).trim());
                }
                Err(e) => eprintln!("warning: subnet route: {}", e),
            }
        }

        (dev, name)
    };

    let tun_ip: Ipv4Addr = cfg.net.tun_ipv4.parse()
        .map_err(|_| format!("invalid TUN IP: {}", cfg.net.tun_ipv4))?;

    // ── 5-6. Create Host (TUN + UDP + IP Allocator) ──────────────────
    #[cfg(feature = "tun")]
    let tun_wrapper = Arc::new(RealTun { dev: tun_dev });

    #[cfg(feature = "tun")]
    let host = {
        let host_cfg = host::Config {
            private_key: key_pair,
            tun_ipv4: tun_ip,
            mtu: tun_mtu as usize,
            listen_port,
            peers: Vec::new(),
            fake_ip_lookup: None,
            fake_ip_handler: None,
        };
        Host::new(host_cfg, tun_wrapper.clone())
            .map_err(|e| format!("create host: {}", e))?
    };

    eprintln!("host listening on {}", host.local_addr());

    // ── 7. Add peers from config ─────────────────────────────────────
    for (domain, peer_cfg) in &cfg.peers {
        let hex_pk = config::pubkey_from_domain(domain)?;
        let pk = Key::from_hex(&hex_pk)
            .map_err(|e| format!("peer {}: invalid pubkey: {}", domain, e))?;

        let endpoint = peer_cfg.direct.first().map(|s| s.as_str()).unwrap_or("");
        host.add_peer(pk, endpoint)
            .map_err(|e| format!("add peer {} ({}): {}", peer_cfg.alias, domain, e))?;

        eprintln!(
            "peer added: {} ({}) endpoint={}",
            peer_cfg.alias,
            &hex_pk[..8],
            endpoint
        );
    }

    // ── 8. Start Magic DNS ───────────────────────────────────────────
    let dns_addr_str = format!("{}:53", tun_ip);
    let dns_server = Arc::new(dns::Server::new(dns::server::ServerConfig {
        listen_addr: dns_addr_str.clone(),
        tun_ipv4: tun_ip,
        upstream: "8.8.8.8:53".to_string(),
        ..Default::default()
    }));

    let dns_socket = UdpSocket::bind(&dns_addr_str)
        .map_err(|e| format!("bind DNS {}: {}", dns_addr_str, e))?;
    let dns_srv = dns_server.clone();
    thread::spawn(move || {
        eprintln!("dns listening on {}", dns_addr_str);
        dns_serve_loop(dns_srv, dns_socket);
    });

    // Configure OS to route *.zigor.net DNS queries to our server
    #[cfg(feature = "dnsmgr")]
    {
        match dnsmgr::Manager::new(Some(&tun_name)) {
            Ok(mgr) => {
                if let Err(e) = mgr.set_dns(&tun_ip.to_string(), &["zigor.net"]) {
                    eprintln!("warning: dnsmgr set DNS failed: {}", e);
                } else {
                    eprintln!("dns: OS configured to resolve *.zigor.net via {}", tun_ip);
                }
                // Keep mgr alive — it cleans up on drop
                std::mem::forget(mgr);
            }
            Err(e) => {
                eprintln!("warning: dnsmgr init failed (split DNS will not work): {}", e);
            }
        }
    }

    // ── 9. Start SOCKS5 Proxy (dials through KCP tunnel) ─────────────
    let proxy_addr = format!("{}:1080", tun_ip);
    let udp_transport = host.udp().clone();

    // Sync SOCKS5 proxy (matching Go's sync approach)
    let proxy_listener = std::net::TcpListener::bind(&proxy_addr)
        .map_err(|e| format!("bind proxy {}: {}", proxy_addr, e))?;
    let udp_for_proxy = udp_transport.clone();
    thread::spawn(move || {
        eprintln!("proxy listening on {} (SOCKS5 → tunnel)", proxy_addr);
        for stream in proxy_listener.incoming() {
            if let Ok(conn) = stream {
                let udp = udp_for_proxy.clone();
                thread::spawn(move || {
                    handle_socks5_proxy(conn, &udp);
                });
            }
        }
    });

    // ── 10. Create Handler Registry + Control Socket ──────────────────
    let handler_dir = data_dir.join("handlers");
    std::fs::create_dir_all(&handler_dir)
        .map_err(|e| format!("create handler dir: {}", e))?;
    let registry = Arc::new(listener::Registry::new(
        handler_dir.to_str().unwrap_or("/tmp/handlers"),
    ));

    let control_sock_path = data_dir.join("control.sock");
    let _ = std::fs::remove_file(&control_sock_path);
    let control_ln = std::os::unix::net::UnixListener::bind(&control_sock_path)
        .map_err(|e| format!("bind control socket: {}", e))?;
    let reg_for_control = Arc::clone(&registry);
    thread::spawn(move || {
        serve_control_socket(control_ln, &reg_for_control);
    });
    eprintln!("control socket: {:?}", control_sock_path);

    // ── 10b. Accept incoming streams via registry dispatch ───────────
    for domain in cfg.peers.keys() {
        if let Ok(hex_pk) = config::pubkey_from_domain(domain) {
            if let Ok(pk) = Key::from_hex(&hex_pk) {
                let udp = udp_transport.clone();
                let reg = Arc::clone(&registry);
                thread::spawn(move || {
                    accept_and_dispatch(&udp, pk, &reg);
                });
            }
        }
    }

    // ── 11. Start RESTful API server ────────────────────────────────
    let api_addr = format!("{}:80", tun_ip);
    let config_mgr = Arc::new(config::Manager::new(cfg_path)
        .map_err(|e| format!("config manager: {}", e))?);
    let mut api_srv = api::Server::new(api::ServerConfig {
        listen_addr: api_addr.clone(),
        host: host.clone(),
        config_mgr,
    }).map_err(|e| format!("api server: {}", e))?;

    thread::spawn(move || {
        eprintln!("api listening on {}", api_addr);
        api_srv.serve();
    });

    // ── 12. Start Host forwarding + wait for signal ──────────────────
    host.run();

    eprintln!("zgrnetd running (pid {})", std::process::id());
    eprintln!("  TUN:   {}/10", tun_ip);
    eprintln!("  UDP:   {}", host.local_addr());
    eprintln!("  DNS:   {}:53", tun_ip);
    eprintln!("  Proxy: {}:1080", tun_ip);
    eprintln!("  API:   {}:80", tun_ip);
    eprintln!("  Peers: {}", cfg.peers.len());

    // Wait for SIGINT / SIGTERM
    wait_for_signal();
    eprintln!("shutting down...");

    // Force exit on second signal or after timeout.
    // Close() calls may block on active connections with in-flight io::copy.
    thread::spawn(|| {
        thread::sleep(Duration::from_secs(5));
        eprintln!("shutdown timeout (5s), force exit");
        std::process::exit(1);
    });

    // Graceful shutdown
    host.close();

    // Remove TUN routes on macOS
    if cfg!(target_os = "macos") {
        let _ = std::process::Command::new("/sbin/route")
            .args(["delete", "-net", "100.64.0.0/10"]).output();
        let _ = std::process::Command::new("/sbin/route")
            .args(["delete", "-host", &tun_ip.to_string()]).output();
        eprintln!("route: cleaned up TUN routes");
    }

    Ok(())
}

// ============================================================================
// DNS serve loop
// ============================================================================

fn dns_serve_loop(server: Arc<dns::Server>, socket: UdpSocket) {
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
// SOCKS5 proxy handler (sync, tunnels through KCP)
// ============================================================================

fn handle_socks5_proxy(mut conn: TcpStream, udp: &zgrnet::net::UDP) {
    conn.set_read_timeout(Some(Duration::from_secs(10))).ok();

    // Auth negotiation
    let mut header = [0u8; 2];
    if conn.read_exact(&mut header).is_err() || header[0] != 0x05 {
        return;
    }
    let mut methods = vec![0u8; header[1] as usize];
    if conn.read_exact(&mut methods).is_err() {
        return;
    }
    if conn.write_all(&[0x05, 0x00]).is_err() {
        return;
    }

    // CONNECT request
    let mut req = [0u8; 4];
    if conn.read_exact(&mut req).is_err() || req[1] != 0x01 {
        let _ = conn.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        return;
    }

    let addr = match req[3] {
        0x01 => {
            // IPv4
            let mut ab = [0u8; 6];
            if conn.read_exact(&mut ab).is_err() { return; }
            let ip = format!("{}.{}.{}.{}", ab[0], ab[1], ab[2], ab[3]);
            let port = u16::from_be_bytes([ab[4], ab[5]]);
            address::Address { atyp: address::ATYP_IPV4, host: ip, port }
        }
        0x03 => {
            // Domain
            let mut lb = [0u8; 1];
            if conn.read_exact(&mut lb).is_err() { return; }
            let mut b = vec![0u8; lb[0] as usize + 2];
            if conn.read_exact(&mut b).is_err() { return; }
            let len = lb[0] as usize;
            let host = String::from_utf8_lossy(&b[..len]).to_string();
            let port = u16::from_be_bytes([b[len], b[len + 1]]);
            address::Address { atyp: address::ATYP_DOMAIN, host, port }
        }
        0x04 => {
            // IPv6
            let mut ab = [0u8; 18];
            if conn.read_exact(&mut ab).is_err() { return; }
            let segs: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([ab[i * 2], ab[i * 2 + 1]])))
                .collect();
            let host = segs.join(":");
            let port = u16::from_be_bytes([ab[16], ab[17]]);
            address::Address { atyp: address::ATYP_IPV6, host, port }
        }
        _ => return,
    };

    // Find an established peer to tunnel through
    let mut target_pk = None;
    for peer in udp.peers() {
        if peer.info.state == zgrnet::net::PeerState::Established {
            target_pk = Some(peer.info.public_key);
            break;
        }
    }

    let target_pk = match target_pk {
        Some(pk) => pk,
        None => {
            // No tunnel peer — direct TCP fallback
            let target = format!("{}:{}", addr.host, addr.port);
            eprintln!("proxy: no tunnel peer, direct dial {}", target);
            match target.parse::<SocketAddr>() {
                Ok(sa) => {
                    match TcpStream::connect_timeout(&sa, Duration::from_secs(10)) {
                        Ok(mut remote) => {
                            let _ = conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                            let mut remote2 = remote.try_clone().unwrap();
                            let mut conn2 = conn.try_clone().unwrap();
                            let t = thread::spawn(move || {
                                let _ = io::copy(&mut remote2, &mut conn2);
                            });
                            let _ = io::copy(&mut conn, &mut remote);
                            let _ = t.join();
                        }
                        Err(_) => {
                            let _ = conn.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                        }
                    }
                }
                Err(_) => {
                    let _ = conn.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                }
            }
            return;
        }
    };

    // Open KCP stream with TCP_PROXY proto + target address as metadata
    let metadata = match addr.encode() {
        Ok(m) => m,
        Err(_) => {
            let _ = conn.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            return;
        }
    };

    let stream = match udp.open_stream(&target_pk, protocol::TCP_PROXY, &metadata) {
        Ok(s) => s,
        Err(_) => {
            let _ = conn.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            return;
        }
    };

    eprintln!(
        "proxy: tunnel {}:{} via {}",
        addr.host,
        addr.port,
        &hex::encode(target_pk)[..8]
    );

    // Success reply
    let _ = conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

    // Relay bidirectionally
    let mut sio = StreamIo(stream);
    let kcp_stream = sio.0.clone();
    let mut conn2 = conn.try_clone().unwrap();
    let t = thread::spawn(move || {
        let mut kcp_w = StreamIo(kcp_stream);
        let _ = copy_32k(&mut conn2, &mut kcp_w);
    });
    let _ = copy_32k(&mut sio, &mut conn);
    let _ = t.join();
}

// ============================================================================
// Registry-based stream dispatch
// ============================================================================

fn accept_and_dispatch(udp: &zgrnet::net::UDP, pk: Key, registry: &Arc<listener::Registry>) {
    loop {
        let stream = match udp.accept_stream(&pk) {
            Ok(s) => s,
            Err(_) => return,
        };

        let proto = stream.proto();
        let handler_idx = match registry.lookup(proto) {
            Some(idx) => idx,
            None => {
                eprintln!(
                    "stream from {}: no handler for proto {}, rejecting",
                    &hex::encode(pk)[..8],
                    proto
                );
                stream.shutdown();
                continue;
            }
        };

        // Get handler info for connecting.
        if let Some(handler) = registry.handler(handler_idx) {
            let sock_path = if handler.target.is_empty() {
                handler.sock.clone()
            } else {
                handler.target.clone()
            };
            let name = handler.name.clone();
            handler.add_active(1);
            drop(handler);

            let metadata = stream.metadata().to_vec();
            let reg_clone = Arc::clone(registry);

            thread::spawn(move || {
                relay_to_handler(stream, pk, &sock_path, &name, proto, &metadata);
                reg_clone.handler(handler_idx).map(|h| h.add_active(-1));
            });
        } else {
            stream.shutdown();
        }
    }
}

fn relay_to_handler(
    stream: Arc<zgrnet::kcp::Stream>,
    pk: Key,
    sock_path: &str,
    handler_name: &str,
    proto: u8,
    metadata: &[u8],
) {
    let path = if sock_path.starts_with("unix://") {
        &sock_path[7..]
    } else {
        sock_path
    };

    let mut conn = match std::os::unix::net::UnixStream::connect(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("handler {:?} connect: {}", handler_name, e);
            stream.shutdown();
            return;
        }
    };

    if let Err(e) = listener::write_stream_header(&mut conn, &pk.0, proto, metadata) {
        eprintln!("handler {:?} write header: {}", handler_name, e);
        stream.shutdown();
        return;
    }

    let mut sio = StreamIo(stream);
    let kcp = sio.0.clone();
    let mut conn2 = conn.try_clone().unwrap();
    let t = thread::spawn(move || {
        let mut kcp_w = StreamIo(kcp);
        let _ = copy_32k(&mut conn2, &mut kcp_w);
    });
    let _ = copy_32k(&mut sio, &mut conn);
    let _ = t.join();
}

// ============================================================================
// Control socket for Listener SDK registrations
// ============================================================================

fn serve_control_socket(ln: std::os::unix::net::UnixListener, registry: &listener::Registry) {
    for stream in ln.incoming() {
        if let Ok(mut conn) = stream {
            let mut buf = vec![0u8; 4096];
            if let Ok(n) = conn.read(&mut buf) {
                let req_str = String::from_utf8_lossy(&buf[..n]);
                // Simple JSON parse for proto, name, mode.
                let proto = parse_json_u8(&req_str, "proto").unwrap_or(0);
                let name = parse_json_str(&req_str, "name").unwrap_or_default();
                let mode_str = parse_json_str(&req_str, "mode").unwrap_or_else(|| "stream".to_string());
                let mode = if mode_str == "dgram" {
                    listener::Mode::Dgram
                } else {
                    listener::Mode::Stream
                };

                match registry.register(proto, &name, mode, "") {
                    Ok(idx) => {
                        if let Some(handler) = registry.handler(idx) {
                            let resp = format!(
                                r#"{{"sock":"{}"}}"#,
                                handler.sock
                            );
                            eprintln!("handler registered: {} (proto={}, sock={})", name, proto, handler.sock);
                            let _ = conn.write_all(resp.as_bytes());
                        }
                    }
                    Err(e) => {
                        let resp = format!(r#"{{"error":"{}"}}"#, e);
                        let _ = conn.write_all(resp.as_bytes());
                    }
                }
            }
        }
    }
}

fn parse_json_str(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn parse_json_u8(json: &str, key: &str) -> Option<u8> {
    let pattern = format!("\"{}\":", key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

// ============================================================================
// Key management
// ============================================================================

fn load_or_generate_key(path: &str) -> Result<KeyPair, Box<dyn std::error::Error>> {
    if let Ok(data) = std::fs::read_to_string(path) {
        let hex_str: String = data.chars().filter(|c| !c.is_whitespace()).collect();
        if hex_str.len() != 64 {
            return Err(format!(
                "invalid key file {}: expected 64 hex chars, got {}",
                path,
                hex_str.len()
            )
            .into());
        }
        let key = Key::from_hex(&hex_str)
            .map_err(|e| format!("invalid key hex: {}", e))?;
        return Ok(KeyPair::from_private(key));
    }

    // File doesn't exist — generate new key
    eprintln!("generating new private key: {}", path);
    let kp = KeyPair::generate();

    if let Some(dir) = Path::new(path).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let hex_key = format!("{}\n", hex::encode(kp.private));
    std::fs::write(path, &hex_key)?;

    Ok(kp)
}

// ============================================================================
// TUN device wrapper
// ============================================================================

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
        Ok(()) // Device closes on drop
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn copy_32k(r: &mut dyn Read, w: &mut dyn Write) -> io::Result<u64> {
    let mut buf = [0u8; 32 * 1024];
    let mut total = 0u64;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        w.write_all(&buf[..n])?;
        total += n as u64;
    }
}

fn wait_for_signal() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc_register(r);

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(100));
    }
}

fn ctrlc_register(running: Arc<std::sync::atomic::AtomicBool>) {
    // Use libc to register SIGINT and SIGTERM
    unsafe {
        libc::signal(libc::SIGINT, signal_handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_handler as libc::sighandler_t);
    }
    // Store the flag globally for the signal handler
    SIGNAL_FLAG
        .lock()
        .unwrap()
        .replace(running);
}

static SIGNAL_FLAG: std::sync::Mutex<Option<Arc<std::sync::atomic::AtomicBool>>> =
    std::sync::Mutex::new(None);

static SIGNAL_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

extern "C" fn signal_handler(_sig: libc::c_int) {
    let count = SIGNAL_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if count >= 1 {
        // Second signal — force exit immediately
        std::process::exit(1);
    }
    if let Ok(guard) = SIGNAL_FLAG.lock() {
        if let Some(flag) = guard.as_ref() {
            flag.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
}
