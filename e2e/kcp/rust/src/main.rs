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
    #[serde(default)]
    mode: String,
    #[serde(default)]
    echo_message: String,
    #[serde(default)]
    throughput_mb: usize,
    #[serde(default)]
    chunk_kb: usize,
    #[serde(default)]
    num_streams: usize,
    #[serde(default)]
    delay_ms: u64,
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    // Run everything inside the runtime so all threads have access.
    rt.block_on(async { tokio::task::spawn_blocking(run).await.unwrap() })
}

fn run() {

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

        let mut established = false;
        for i in 0..100 {
            if let Some(info) = udp.peer_info(&peer_kp.public) {
                eprintln!("[{}] peer state ({}): {:?}", name, i, info.state);
                if info.state == zgrnet::PeerState::Established {
                    established = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
        if !established {
            panic!("session never established after 5 seconds");
        }
        thread::sleep(Duration::from_millis(200));

        run_opener(&udp, &peer_kp.public, &config.test);
    } else {
        eprintln!("[{}] Waiting for connection...", name);
        run_accepter(&udp, &peer_kp.public, &config.test);
    }

    eprintln!("[{}] Test completed successfully!", name);
    udp.close().unwrap();
}

fn run_opener(udp: &Arc<UDP>, peer_pk: &Key, cfg: &TestConfig) {
    let mode = if cfg.mode.is_empty() { "echo" } else { &cfg.mode };

    let mut stream = udp.open_stream(peer_pk, service::PROXY)
        .expect("open_stream failed");
    eprintln!("[opener] Opened stream (mode={})", mode);

    match mode {
        "echo" => {
            stream.write_all(cfg.echo_message.as_bytes()).unwrap();
            eprintln!("[opener] Sent: {:?}", cfg.echo_message);
            let mut buf = vec![0u8; 4096];
            let n = read_with_timeout(&mut stream, &mut buf, Duration::from_secs(10))
                .expect("echo read failed");
            eprintln!("[opener] Response: {:?}", String::from_utf8_lossy(&buf[..n]));
        }
        "streaming" => {
            let total = cfg.throughput_mb * 1024 * 1024;
            let chunk_size = if cfg.chunk_kb > 0 { cfg.chunk_kb * 1024 } else { 8192 };
            let chunk: Vec<u8> = (0..chunk_size).map(|i| (i % 256) as u8).collect();
            let mut sent = 0;
            while sent < total {
                let n = stream.write(&chunk).unwrap();
                sent += n;
            }
            eprintln!("[opener] Sent {} bytes", sent);
        }
        "multi_stream" => {
            let num = if cfg.num_streams > 0 { cfg.num_streams } else { 10 };
            let data: Vec<u8> = (0..100 * 1024).map(|i| (i % 256) as u8).collect();
            stream.write_all(&data).unwrap();

            let mut handles = Vec::new();
            for i in 1..num {
                let mut s = udp.open_stream(peer_pk, service::PROXY)
                    .unwrap_or_else(|e| panic!("open stream {}: {}", i, e));
                let data = data.clone();
                handles.push(thread::spawn(move || {
                    s.write_all(&data).unwrap();
                    eprintln!("[opener] stream {}: sent {} bytes", i, data.len());
                    s.close();
                }));
            }
            for h in handles { h.join().unwrap(); }
            eprintln!("[opener] all {} streams done", num);
        }
        "delayed_write" => {
            let delay = if cfg.delay_ms > 0 { cfg.delay_ms } else { 2000 };
            eprintln!("[opener] delaying {}ms...", delay);
            thread::sleep(Duration::from_millis(delay));
            stream.write_all(b"delayed hello").unwrap();
            let mut buf = vec![0u8; 4096];
            let n = read_with_timeout(&mut stream, &mut buf, Duration::from_secs(10))
                .expect("delayed read failed");
            eprintln!("[opener] delayed response: {:?}", String::from_utf8_lossy(&buf[..n]));
        }
        _ => panic!("unknown mode: {}", mode),
    }

    thread::sleep(Duration::from_secs(1));
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

    let mode = if cfg.mode.is_empty() { "echo" } else { &cfg.mode };

    match mode {
        "echo" | "delayed_write" => {
            let (mut stream, _svc) = udp.accept_stream(peer_pk).expect("accept failed");
            let mut buf = vec![0u8; 4096];
            let n = read_with_timeout(&mut stream, &mut buf, Duration::from_secs(30))
                .expect("read failed");
            eprintln!("[accepter] Received: {:?}", String::from_utf8_lossy(&buf[..n]));
            let response = format!("Echo: {}", String::from_utf8_lossy(&buf[..n]));
            stream.write_all(response.as_bytes()).unwrap();
            stream.close();
        }
        "streaming" => {
            let (mut stream, _svc) = udp.accept_stream(peer_pk).expect("accept failed");
            let total = cfg.throughput_mb * 1024 * 1024;
            let mut buf = vec![0u8; 65536];
            let mut recv = 0;
            while recv < total {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => recv += n,
                    Err(_) => break,
                }
            }
            eprintln!("[accepter] Received {} / {} bytes", recv, total);
            if recv < total { panic!("incomplete: {} < {}", recv, total); }
            stream.close();
        }
        "multi_stream" => {
            let num = if cfg.num_streams > 0 { cfg.num_streams } else { 10 };
            let mut handles = Vec::new();
            for i in 0..num {
                let (mut stream, _svc) = udp.accept_stream(peer_pk)
                    .unwrap_or_else(|e| panic!("accept {}: {}", i, e));
                handles.push(thread::spawn(move || {
                    let mut buf = vec![0u8; 65536];
                    let mut total = 0;
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => total += n,
                            Err(_) => break,
                        }
                    }
                    eprintln!("[accepter] stream {}: received {} bytes", i, total);
                    stream.close();
                }));
            }
            for h in handles { h.join().unwrap(); }
            eprintln!("[accepter] all {} streams done", num);
        }
        _ => panic!("unknown mode: {}", mode),
    }

    thread::sleep(Duration::from_secs(1));
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
