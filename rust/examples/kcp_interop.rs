//! KCP stream interoperability test between Rust and Go.
//!
//! Usage:
//!   cargo run --example kcp_interop -- --name rust --config ../examples/kcp_test/config.json

use std::env;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use zgrnet::{Key, KeyPair, Stream};
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
    let args: Vec<String> = env::args().collect();
    let name = args
        .iter()
        .position(|x| x == "--name")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .expect("Usage: --name <name> --config <path>");

    let config_path = args
        .iter()
        .position(|x| x == "--config")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.to_string())
        .expect("Usage: --name <name> --config <path>");

    let config_data = fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("Failed to read config {}: {}", config_path, e));
    let config: Config = serde_json::from_str(&config_data)
        .unwrap_or_else(|e| panic!("Failed to parse config: {}", e));

    // Find our host
    let my_host = config
        .hosts
        .iter()
        .find(|h| h.name == name)
        .unwrap_or_else(|| panic!("Host {} not found in config", name));

    // Parse private key
    let priv_key_bytes = hex::decode(&my_host.private_key)
        .unwrap_or_else(|e| panic!("Invalid private key: {}", e));
    let mut priv_key = [0u8; 32];
    priv_key.copy_from_slice(&priv_key_bytes);
    let key_pair = KeyPair::from_private(Key::from(priv_key));

    println!("[{}] Public key: {}...", name, hex::encode(&key_pair.public.as_bytes()[..8]));
    println!("[{}] Role: {}", name, my_host.role);

    // Create UDP
    let bind_addr = format!("0.0.0.0:{}", my_host.port);
    let udp = Arc::new(UDP::new(
        key_pair.clone(),
        UdpOptions::new().bind_addr(&bind_addr).allow_unknown(true),
    ).unwrap_or_else(|e| panic!("Failed to create UDP: {}", e)));

    let info = udp.host_info();
    println!("[{}] Listening on {}", name, info.addr);

    // Find peer (first host that is not us)
    let peer_host = config
        .hosts
        .iter()
        .find(|h| h.name != name)
        .unwrap_or_else(|| panic!("No peer found in config"));

    let peer_priv_bytes = hex::decode(&peer_host.private_key).unwrap();
    let mut peer_priv = [0u8; 32];
    peer_priv.copy_from_slice(&peer_priv_bytes);
    let peer_kp = KeyPair::from_private(Key::from(peer_priv));

    // Add peer endpoint
    let endpoint: SocketAddr = format!("127.0.0.1:{}", peer_host.port).parse().unwrap();
    udp.set_peer_endpoint(peer_kp.public, endpoint);
    println!("[{}] Added peer {} at port {}", name, peer_host.name, peer_host.port);

    // Start receive loop in background
    let udp_recv = Arc::clone(&udp);
    thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        loop {
            if udp_recv.is_closed() {
                break;
            }
            // Consume non-KCP packets
            let _ = udp_recv.read_from(&mut buf);
        }
    });

    // Run test based on role
    let role = my_host.role.as_str();
    if role == "opener" {
        // Wait for peer to start
        println!("[{}] Waiting for peer to start...", name);
        thread::sleep(Duration::from_secs(2));

        // Opener initiates connection
        println!("[{}] Connecting to {}...", name, peer_host.name);
        udp.connect(&peer_kp.public).unwrap_or_else(|e| panic!("Failed to connect: {}", e));
        println!("[{}] Connected to {}!", name, peer_host.name);

        // Give time for mux initialization
        thread::sleep(Duration::from_millis(100));

        run_opener_test(&udp, &peer_kp.public, &peer_host.name, &config.test);
    } else {
        // Accepter waits for incoming connection, then accepts stream
        println!("[{}] Waiting for connection from {}...", name, peer_host.name);
        run_accepter_test(&udp, &peer_kp.public, &peer_host.name, &config.test);
    }

    println!("[{}] Test completed successfully!", name);
    udp.close().unwrap();
}

fn run_opener_test(udp: &Arc<UDP>, peer_pk: &Key, peer_name: &str, test_cfg: &TestConfig) {
    println!("[opener] Opening stream to {}...", peer_name);

    let stream = udp.open_stream(peer_pk)
        .unwrap_or_else(|e| panic!("Failed to open stream: {}", e));

    println!("[opener] Opened stream {}", stream.id());

    // Echo test
    println!("[opener] Running echo test...");
    let echo_msg = test_cfg.echo_message.as_bytes();
    stream.write_data(echo_msg)
        .unwrap_or_else(|e| panic!("Failed to write echo: {}", e));
    println!("[opener] Sent {} bytes: {:?}", echo_msg.len(), test_cfg.echo_message);

    // Read echo response
    let response = read_with_timeout(&stream, Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("Failed to read echo response: {}", e));
    println!("[opener] Received echo response: {:?}", String::from_utf8_lossy(&response));

    // Bidirectional throughput test
    run_bidirectional_test(&stream, "opener", test_cfg);

    stream.shutdown();
}

fn run_accepter_test(udp: &Arc<UDP>, peer_pk: &Key, peer_name: &str, test_cfg: &TestConfig) {
    // Wait for peer to connect and establish session
    println!("[accepter] Waiting for {} to connect...", peer_name);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if Instant::now() > deadline {
            panic!("Timeout waiting for peer connection");
        }
        if let Some(info) = udp.peer_info(peer_pk) {
            if info.state == zgrnet::PeerState::Established {
                println!("[accepter] Session established with {}", peer_name);
                break;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Give mux time to initialize
    thread::sleep(Duration::from_millis(100));

    println!("[accepter] Waiting to accept stream from {}...", peer_name);

    let stream = udp.accept_stream(peer_pk)
        .unwrap_or_else(|e| panic!("Failed to accept stream: {}", e));

    println!("[accepter] Accepted stream {}", stream.id());

    // Echo test - receive and echo back
    let received = read_with_timeout(&stream, Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("Failed to read echo: {}", e));
    let received_str = String::from_utf8_lossy(&received);
    println!("[accepter] Received echo: {:?}", received_str);

    // Echo back with prefix
    let response = format!("Echo from accepter: {}", received_str);
    stream.write_data(response.as_bytes())
        .unwrap_or_else(|e| panic!("Failed to write echo response: {}", e));
    println!("[accepter] Sent echo response: {:?}", response);

    // Bidirectional throughput test
    run_bidirectional_test(&stream, "accepter", test_cfg);

    // Wait for remaining data to flush before closing
    thread::sleep(Duration::from_secs(1));
    stream.shutdown();
}

use std::sync::atomic::{AtomicU64, Ordering};

fn run_bidirectional_test(stream: &Arc<Stream>, role: &str, test_cfg: &TestConfig) {
    let total_bytes = (test_cfg.throughput_mb * 1024 * 1024) as u64;
    let chunk_size = test_cfg.chunk_kb * 1024;

    println!("[{}] Starting bidirectional test: {} MB each direction, {} KB chunks",
             role, test_cfg.throughput_mb, test_cfg.chunk_kb);

    let sent_bytes = Arc::new(AtomicU64::new(0));
    let recv_bytes = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    // Writer thread
    let stream_tx = Arc::clone(stream);
    let sent_bytes_tx = Arc::clone(&sent_bytes);
    let role_tx = role.to_string();
    let tx_handle = thread::spawn(move || {
        let chunk: Vec<u8> = (0..chunk_size).map(|i| (i % 256) as u8).collect();
        let mut sent: u64 = 0;

        while sent < total_bytes {
            match stream_tx.write_data(&chunk) {
                Ok(n) => {
                    sent += n as u64;
                    sent_bytes_tx.store(sent, Ordering::Relaxed);

                    // Progress every 10%
                    if sent % (total_bytes / 10) < chunk_size as u64 {
                        println!("[{}] TX: {:.1}%", role_tx, sent as f64 / total_bytes as f64 * 100.0);
                    }
                }
                Err(e) => {
                    println!("[{}] Write error: {:?}", role_tx, e);
                    return;
                }
            }
        }
        println!("[{}] TX complete: {} bytes", role_tx, sent);
    });

    // Reader thread
    let stream_rx = Arc::clone(stream);
    let recv_bytes_rx = Arc::clone(&recv_bytes);
    let role_rx = role.to_string();
    let rx_handle = thread::spawn(move || {
        let mut buf = vec![0u8; chunk_size * 4]; // Larger buffer
        let mut recv: u64 = 0;
        let mut idle_count = 0u32;

        while recv < total_bytes {
            match stream_rx.read_data(&mut buf) {
                Ok(n) if n > 0 => {
                    recv += n as u64;
                    recv_bytes_rx.store(recv, Ordering::Relaxed);
                    idle_count = 0;
                }
                Ok(_) => {
                    idle_count += 1;
                    if idle_count > 100 {
                        thread::sleep(Duration::from_micros(10));
                    }
                }
                Err(e) => {
                    println!("[{}] Read error: {:?}", role_rx, e);
                    return;
                }
            }
        }
        println!("[{}] RX complete: {} bytes", role_rx, recv);
    });

    tx_handle.join().unwrap();
    rx_handle.join().unwrap();

    let elapsed = start.elapsed();
    let sent = sent_bytes.load(Ordering::Relaxed);
    let recv = recv_bytes.load(Ordering::Relaxed);
    let total_transfer = sent + recv;
    let throughput = total_transfer as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0;

    println!("[{}] ========== Bidirectional Results ==========", role);
    println!("[{}] Sent:       {} bytes ({:.2} GB)", role, sent, sent as f64 / 1024.0 / 1024.0 / 1024.0);
    println!("[{}] Received:   {} bytes ({:.2} GB)", role, recv, recv as f64 / 1024.0 / 1024.0 / 1024.0);
    println!("[{}] Total:      {} bytes ({:.2} GB)", role, total_transfer, total_transfer as f64 / 1024.0 / 1024.0 / 1024.0);
    println!("[{}] Time:       {:?}", role, elapsed);
    println!("[{}] Throughput: {:.2} MB/s (bidirectional)", role, throughput);
    println!("[{}] ============================================", role);
}

/// Read data from stream with timeout, returns accumulated data.
fn read_with_timeout(stream: &Arc<Stream>, timeout: Duration) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 4096];
    let mut result = Vec::new();

    while Instant::now() < deadline {
        match stream.read_data(&mut buf) {
            Ok(n) if n > 0 => {
                result.extend_from_slice(&buf[..n]);
                return Ok(result);
            }
            Ok(_) => thread::sleep(Duration::from_millis(1)),
            Err(e) => return Err(format!("{:?}", e)),
        }
    }

    Err(format!("Read timeout after {:?}", timeout))
}
