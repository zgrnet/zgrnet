//! KCP stream multiplexing demo over Noise-encrypted connections.
//!
//! This example creates two local peers, establishes a connection, opens/accepts streams,
//! and measures throughput.
//!
//! Usage:
//!   cargo run --example stream_test -- [--size <MB>] [--chunk <KB>] [--no-echo]
//!
//! Or with Bazel:
//!   bazel run //rust:stream_test_example

use std::env;
use std::io::{self, Write as IoWrite};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use zgrnet::{KeyPair, UDP, UdpOptions, Stream};

fn main() {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let data_size_mb = parse_arg(&args, "--size", 10);
    let chunk_size_kb = parse_arg(&args, "--chunk", 32);
    let run_echo = !args.contains(&"--no-echo".to_string());

    println!("[config] Data size: {} MB, Chunk size: {} KB, Echo test: {}",
             data_size_mb, chunk_size_kb, run_echo);

    // Generate keypairs
    let server_key = KeyPair::generate();
    let client_key = KeyPair::generate();

    println!("[server] Public key: {}...", hex::encode(&server_key.public.as_bytes()[..8]));
    println!("[client] Public key: {}...", hex::encode(&client_key.public.as_bytes()[..8]));

    // Create UDP instances
    let server = Arc::new(
        UDP::new(server_key.clone(), UdpOptions::new().bind_addr("127.0.0.1:0").allow_unknown(true))
            .expect("Failed to create server UDP")
    );
    let client = Arc::new(
        UDP::new(client_key.clone(), UdpOptions::new().bind_addr("127.0.0.1:0").allow_unknown(true))
            .expect("Failed to create client UDP")
    );

    let server_addr = server.host_info().addr;
    let client_addr = client.host_info().addr;

    println!("[server] Listening on {}", server_addr);
    println!("[client] Listening on {}", client_addr);

    // Set up peer endpoints
    server.set_peer_endpoint(client_key.public, client_addr);
    client.set_peer_endpoint(server_key.public, server_addr);

    // Start receive loops to consume ReadFrom output
    let server_clone = Arc::clone(&server);
    let read_from_count = Arc::new(AtomicU64::new(0));
    let read_from_count_clone = Arc::clone(&read_from_count);
    let server_recv_handle = thread::spawn(move || {
        receive_loop(server_clone, "server", read_from_count_clone);
    });

    let client_clone = Arc::clone(&client);
    let read_from_count_clone2 = Arc::clone(&read_from_count);
    let client_recv_handle = thread::spawn(move || {
        receive_loop(client_clone, "client", read_from_count_clone2);
    });

    // Client connects to server
    println!("[client] Connecting to server...");
    client.connect(&server_key.public).expect("Failed to connect");
    println!("[client] Connected to server!");

    // Give time for handshake to complete on server side
    thread::sleep(Duration::from_millis(100));

    // Run KCP stream benchmark
    run_kcp_benchmark(
        Arc::clone(&client),
        Arc::clone(&server),
        &client_key,
        &server_key,
        data_size_mb,
        chunk_size_kb,
        run_echo,
    );

    println!("[done] All tests completed successfully!");
    println!("[stats] ReadFrom consumed: {} packets", read_from_count.load(Ordering::Relaxed));

    // Close UDP instances
    server.close().unwrap();
    client.close().unwrap();

    // Wait for receive threads to finish
    let _ = server_recv_handle.join();
    let _ = client_recv_handle.join();
}

fn parse_arg(args: &[String], name: &str, default: usize) -> usize {
    args.iter()
        .position(|x| x == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn receive_loop(udp: Arc<UDP>, _name: &str, count: Arc<AtomicU64>) {
    let mut buf = vec![0u8; 65535];
    loop {
        if udp.is_closed() {
            break;
        }
        match udp.read_from(&mut buf) {
            Ok((_, n)) => {
                if n > 0 {
                    count.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(_) => {
                // Ignore errors, continue
            }
        }
    }
}

fn run_kcp_benchmark(
    client: Arc<UDP>,
    server: Arc<UDP>,
    client_key: &KeyPair,
    server_key: &KeyPair,
    data_size_mb: usize,
    chunk_size_kb: usize,
    run_echo: bool,
) {
    // Server accepts stream in background
    let server_key_pub = server_key.public;
    let client_key_pub = client_key.public;
    let server_clone = Arc::clone(&server);
    
    let (accept_tx, accept_rx) = std::sync::mpsc::channel();
    
    thread::spawn(move || {
        println!("[server] Waiting to accept stream...");
        match server_clone.accept_stream(&client_key_pub) {
            Ok(stream) => {
                println!("[server] Accepted stream {}", stream.id());
                let _ = accept_tx.send(Ok(stream));
            }
            Err(e) => {
                println!("[server] AcceptStream failed: {}", e);
                let _ = accept_tx.send(Err(e));
            }
        }
    });

    // Client opens stream
    println!("[client] Opening stream...");
    let client_stream = client.open_stream(&server_key_pub, 0, &[])
        .expect("Failed to open stream");
    println!("[client] Opened stream {}", client_stream.id());

    // Wait for server to accept
    let server_stream = accept_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("Timeout waiting for server to accept stream")
        .expect("Server failed to accept stream");

    // Run echo test
    if run_echo {
        run_echo_test(&client_stream, &server_stream);
    }

    // Run throughput benchmark
    run_stream_benchmark(&client_stream, &server_stream, data_size_mb, chunk_size_kb);

    // Close streams
    client_stream.shutdown();
    server_stream.shutdown();
}

fn run_echo_test(client_stream: &Arc<Stream>, server_stream: &Arc<Stream>) {
    println!("[test] Running echo test...");

    let test_msg = b"Hello KCP Stream!";

    // Client sends
    client_stream.write_data(test_msg).expect("Client write failed");

    // Server reads (poll for data)
    let mut buf = vec![0u8; 1024];
    let received = read_with_poll(server_stream, &mut buf, Duration::from_secs(2));

    if received != test_msg.len() {
        panic!("[test] Echo mismatch: got {} bytes, expected {}", received, test_msg.len());
    }

    if &buf[..received] != test_msg {
        panic!("[test] Echo content mismatch");
    }

    println!("[test] Echo test passed: {:?}", String::from_utf8_lossy(&buf[..received]));
}

fn run_stream_benchmark(
    client_stream: &Arc<Stream>,
    server_stream: &Arc<Stream>,
    data_size_mb: usize,
    chunk_size_kb: usize,
) {
    let total_bytes = (data_size_mb * 1024 * 1024) as u64;
    let chunk_bytes = chunk_size_kb * 1024;

    println!("[bench] Starting KCP BIDIRECTIONAL throughput test: {} MB each direction, chunk size {} KB", data_size_mb, chunk_size_kb);

    // Generate random data
    let chunk: Vec<u8> = (0..chunk_bytes).map(|i| (i % 256) as u8).collect();

    let client_tx = Arc::new(AtomicU64::new(0));
    let client_rx = Arc::new(AtomicU64::new(0));
    let server_tx = Arc::new(AtomicU64::new(0));
    let server_rx = Arc::new(AtomicU64::new(0));

    let start = Instant::now();

    // Spawn 4 threads for bidirectional transfer
    let handles: Vec<_> = vec![
        // Client writer (client -> server)
        {
            let stream = Arc::clone(client_stream);
            let chunk = chunk.clone();
            let tx_bytes = Arc::clone(&client_tx);
            thread::spawn(move || {
                let iterations = (total_bytes as usize) / chunk.len();
                let mut sent: u64 = 0;
                for _ in 0..iterations {
                    match stream.write_data(&chunk) {
                        Ok(n) => sent += n as u64,
                        Err(_) => break,
                    }
                }
                tx_bytes.store(sent, Ordering::SeqCst);
            })
        },
        // Client reader (server -> client)
        {
            let stream = Arc::clone(client_stream);
            let rx_bytes = Arc::clone(&client_rx);
            let chunk_bytes = chunk_bytes;
            thread::spawn(move || {
                let mut buf = vec![0u8; chunk_bytes * 4];
                let mut recv: u64 = 0;
                let deadline = Instant::now() + Duration::from_secs(120);
                while recv < total_bytes && Instant::now() < deadline {
                    match stream.read_data(&mut buf) {
                        Ok(n) if n > 0 => recv += n as u64,
                        Ok(_) => thread::yield_now(), // Yield CPU instead of spin
                        Err(_) => break,
                    }
                }
                rx_bytes.store(recv, Ordering::SeqCst);
            })
        },
        // Server writer (server -> client)
        {
            let stream = Arc::clone(server_stream);
            let chunk = chunk.clone();
            let tx_bytes = Arc::clone(&server_tx);
            thread::spawn(move || {
                let iterations = (total_bytes as usize) / chunk.len();
                let mut sent: u64 = 0;
                for _ in 0..iterations {
                    match stream.write_data(&chunk) {
                        Ok(n) => sent += n as u64,
                        Err(_) => break,
                    }
                }
                tx_bytes.store(sent, Ordering::SeqCst);
            })
        },
        // Server reader (client -> server)
        {
            let stream = Arc::clone(server_stream);
            let rx_bytes = Arc::clone(&server_rx);
            let chunk_bytes = chunk_bytes;
            thread::spawn(move || {
                let mut buf = vec![0u8; chunk_bytes * 4];
                let mut recv: u64 = 0;
                let deadline = Instant::now() + Duration::from_secs(120);
                while recv < total_bytes && Instant::now() < deadline {
                    match stream.read_data(&mut buf) {
                        Ok(n) if n > 0 => recv += n as u64,
                        Ok(_) => thread::yield_now(), // Yield CPU instead of spin
                        Err(_) => break,
                    }
                }
                rx_bytes.store(recv, Ordering::SeqCst);
            })
        },
    ];

    // Wait for all threads
    for h in handles {
        let _ = h.join();
    }

    let elapsed = start.elapsed();

    // Calculate throughput
    let ctx = client_tx.load(Ordering::SeqCst);
    let crx = client_rx.load(Ordering::SeqCst);
    let stx = server_tx.load(Ordering::SeqCst);
    let srx = server_rx.load(Ordering::SeqCst);
    let total_transfer = ctx + crx + stx + srx;
    let throughput_mbps = (total_transfer as f64) / elapsed.as_secs_f64() / 1024.0 / 1024.0;

    println!("[bench] ========== KCP Bidirectional Results ==========");
    println!("[bench] Client TX:  {} bytes ({:.2} MB)", ctx, ctx as f64 / 1024.0 / 1024.0);
    println!("[bench] Client RX:  {} bytes ({:.2} MB)", crx, crx as f64 / 1024.0 / 1024.0);
    println!("[bench] Server TX:  {} bytes ({:.2} MB)", stx, stx as f64 / 1024.0 / 1024.0);
    println!("[bench] Server RX:  {} bytes ({:.2} MB)", srx, srx as f64 / 1024.0 / 1024.0);
    println!("[bench] Total:      {} bytes ({:.2} GB)", total_transfer, total_transfer as f64 / 1024.0 / 1024.0 / 1024.0);
    println!("[bench] Time:       {:?}", elapsed);
    println!("[bench] Throughput: {:.2} MB/s (bidirectional)", throughput_mbps);
    println!("[bench] ================================================");
}

/// Read from stream with polling since read_data() is non-blocking.
fn read_with_poll(stream: &Arc<Stream>, buf: &mut [u8], timeout: Duration) -> usize {
    let deadline = Instant::now() + timeout;
    let mut total = 0;
    let mut spin_count = 0;
    
    while Instant::now() < deadline {
        match stream.read_data(&mut buf[total..]) {
            Ok(n) if n > 0 => {
                total += n;
                spin_count = 0;
                return total; // Return as soon as we get some data
            }
            Ok(_) => {
                // No data available - use adaptive backoff
                spin_count += 1;
                if spin_count > 1000 {
                    // After many spins, sleep briefly
                    thread::sleep(Duration::from_micros(100));
                } else {
                    // Spin without sleeping for low latency
                    std::hint::spin_loop();
                }
            }
            Err(_) => {
                break;
            }
        }
    }
    
    total
}
