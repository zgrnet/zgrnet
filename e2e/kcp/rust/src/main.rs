//! KCP stream interoperability test — Rust side.
//!
//! Usage: kcp_test --name rust --config ../config.json

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};

use zgrnet::noise::message::service;
use zgrnet::{Key, KeyPair, SyncStream};
use zgrnet::{UDP, UdpOptions};

#[derive(serde::Deserialize)]
struct Config {
    hosts: Vec<HostInfo>,
    test: TestConfig,
}

#[derive(serde::Deserialize)]
struct HostInfo {
    name: String,
    private_key: String,
    port: u16,
    role: String,
}

#[derive(serde::Deserialize)]
struct TestConfig {
    echo_message: String,
    throughput_mb: usize,
    chunk_kb: usize,
}

fn main() {
    // ServiceMux requires a tokio runtime for KcpConn run_loop and yamux driver tasks.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");
    let _guard = rt.enter();

    let args: Vec<String> = env::args().collect();
    let name = args.iter().position(|x| x == "--name")
        .and_then(|i| args.get(i + 1)).map(|s| s.as_str())
        .expect("Usage: --name <name> --config <path>");
    let config_path = args.iter().position(|x| x == "--config")
        .and_then(|i| args.get(i + 1)).map(|s| s.to_string())
        .expect("Usage: --name <name> --config <path>");

    let config: Config = serde_json::from_str(
        &fs::read_to_string(&config_path).unwrap()
    ).unwrap();

    let my_host = config.hosts.iter().find(|h| h.name == name)
        .unwrap_or_else(|| panic!("Host {} not found", name));

    let priv_bytes = hex::decode(&my_host.private_key).unwrap();
    let mut priv_key = [0u8; 32];
    priv_key.copy_from_slice(&priv_bytes);
    let key_pair = KeyPair::from_private(Key::from(priv_key));

    eprintln!("[{}] Public key: {}...", name, hex::encode(&key_pair.public.as_bytes()[..8]));
    eprintln!("[{}] Role: {}", name, my_host.role);

    let bind_addr = format!("0.0.0.0:{}", my_host.port);
    let udp = Arc::new(UDP::new(
        key_pair.clone(),
        UdpOptions::new().bind_addr(&bind_addr).allow_unknown(true),
    ).expect("Failed to create UDP"));

    eprintln!("[{}] Listening on {}", name, udp.host_info().addr);

    let peer_host = config.hosts.iter().find(|h| h.name != name)
        .expect("No peer found");

    let peer_priv = hex::decode(&peer_host.private_key).unwrap();
    let mut pp = [0u8; 32];
    pp.copy_from_slice(&peer_priv);
    let peer_kp = KeyPair::from_private(Key::from(pp));

    let endpoint: SocketAddr = format!("127.0.0.1:{}", peer_host.port).parse().unwrap();
    udp.set_peer_endpoint(peer_kp.public, endpoint);

    let udp_recv = Arc::clone(&udp);
    thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        loop {
            if udp_recv.is_closed() { break; }
            let _ = udp_recv.read_from(&mut buf);
        }
    });

    if my_host.role == "opener" {
        eprintln!("[{}] Waiting for peer...", name);
        thread::sleep(Duration::from_secs(2));

        eprintln!("[{}] Connecting...", name);
        udp.connect(&peer_kp.public).expect("connect failed");

        // Wait for session establishment
        for _ in 0..100 {
            if let Some(info) = udp.peer_info(&peer_kp.public) {
                if info.state == zgrnet::PeerState::Established { break; }
            }
            thread::sleep(Duration::from_millis(50));
        }
        thread::sleep(Duration::from_millis(100));

        run_opener(&udp, &peer_kp.public, &config.test);
    } else {
        eprintln!("[{}] Waiting for connection...", name);
        run_accepter(&udp, &peer_kp.public, &config.test);
    }

    eprintln!("[{}] Test completed successfully!", name);
    udp.close().unwrap();
}

fn run_opener(udp: &Arc<UDP>, peer_pk: &Key, cfg: &TestConfig) {
    let mut stream = udp.open_stream(peer_pk, service::PROXY)
        .expect("open_stream failed");

    eprintln!("[opener] Opened stream on service={}", service::PROXY);

    // Echo test: write message, read response.
    // yamux defers SYN until first write, so this also establishes the stream.
    stream.write_all(cfg.echo_message.as_bytes()).unwrap();
    eprintln!("[opener] Sent echo: {:?}", cfg.echo_message);

    let mut buf = vec![0u8; 4096];
    let n = read_with_timeout(&mut stream, &mut buf, Duration::from_secs(5))
        .expect("echo read failed");
    eprintln!("[opener] Echo response: {:?}", String::from_utf8_lossy(&buf[..n]));

    // Bidirectional throughput test.
    run_bidirectional(&mut stream, "opener", cfg);

    thread::sleep(Duration::from_secs(2));
    stream.close();
}

fn run_accepter(udp: &Arc<UDP>, peer_pk: &Key, cfg: &TestConfig) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if Instant::now() > deadline { panic!("timeout waiting for session"); }
        if let Some(info) = udp.peer_info(peer_pk) {
            if info.state == zgrnet::PeerState::Established { break; }
        }
        thread::sleep(Duration::from_millis(100));
    }
    thread::sleep(Duration::from_millis(100));

    let (mut stream, svc) = udp.accept_stream(peer_pk)
        .expect("accept_stream failed");
    eprintln!("[accepter] Accepted stream on service={}", svc);

    // Echo test: read message, echo back.
    let mut buf = vec![0u8; 4096];
    let n = read_with_timeout(&mut stream, &mut buf, Duration::from_secs(5))
        .expect("echo read failed");
    let received = String::from_utf8_lossy(&buf[..n]).to_string();
    eprintln!("[accepter] Received: {:?}", received);

    let response = format!("Echo from accepter: {}", received);
    stream.write_all(response.as_bytes()).unwrap();
    eprintln!("[accepter] Sent response: {:?}", response);

    // Bidirectional throughput test.
    run_bidirectional(&mut stream, "accepter", cfg);

    thread::sleep(Duration::from_secs(1));
    stream.close();
}

fn run_bidirectional(stream: &mut SyncStream, role: &str, cfg: &TestConfig) {
    let total_bytes = (cfg.throughput_mb * 1024 * 1024) as u64;
    let chunk_size = cfg.chunk_kb * 1024;

    eprintln!("[{}] Bidirectional test: {} MB × 2, {} KB chunks", role, cfg.throughput_mb, cfg.chunk_kb);

    let sent_bytes = Arc::new(AtomicU64::new(0));
    let recv_bytes = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    let mut tx_stream = stream.clone();
    let sent = sent_bytes.clone();
    let r = role.to_string();
    let tx = thread::spawn(move || {
        let chunk: Vec<u8> = (0..chunk_size).map(|i| (i % 256) as u8).collect();
        let mut s: u64 = 0;
        while s < total_bytes {
            match tx_stream.write(&chunk) {
                Ok(n) => { s += n as u64; sent.store(s, Ordering::Relaxed); }
                Err(e) => { eprintln!("[{}] write error: {}", r, e); return; }
            }
        }
        eprintln!("[{}] TX done: {} bytes", r, s);
    });

    let mut rx_stream = stream.clone();
    let recvd = recv_bytes.clone();
    let r = role.to_string();
    let rx = thread::spawn(move || {
        let mut buf = vec![0u8; chunk_size * 2];
        let mut recv: u64 = 0;
        while recv < total_bytes {
            match rx_stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => { recv += n as u64; recvd.store(recv, Ordering::Relaxed); }
                Err(e) => { eprintln!("[{}] read error: {}", r, e); return; }
            }
        }
        eprintln!("[{}] RX done: {} bytes", r, recv);
    });

    tx.join().unwrap();
    rx.join().unwrap();

    let elapsed = start.elapsed();
    let s = sent_bytes.load(Ordering::Relaxed);
    let r = recv_bytes.load(Ordering::Relaxed);
    let mbps = (s + r) as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0;
    eprintln!("[{}] Sent={} Recv={} Time={:?} Throughput={:.1} MB/s", role, s, r, elapsed, mbps);
}

fn read_with_timeout(stream: &mut SyncStream, buf: &mut [u8], timeout: Duration) -> Result<usize, String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match stream.read(buf) {
            Ok(0) => thread::sleep(Duration::from_millis(1)),
            Ok(n) => return Ok(n),
            Err(e) => return Err(format!("{}", e)),
        }
    }
    Err("read timeout".into())
}
