//! Rust UDP throughput test with Noise encryption and async pipeline.
//!
//! Usage:
//!   cargo run --release --example throughput_rust -- --size 100

use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zgrnet::{AsyncUDP, AsyncUdpConfig, KeyPair};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let size_mb: usize = args
        .iter()
        .position(|x| x == "--size")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    println!("=== Rust AsyncUDP Throughput Test ===");

    // Generate keys
    let server_key = KeyPair::generate();
    let client_key = KeyPair::generate();

    // Create async UDP instances with pipeline
    let config = AsyncUdpConfig {
        decrypt_workers: 0, // Use CPU count
        ..Default::default()
    };

    let server = AsyncUDP::new(server_key.clone(), "127.0.0.1:0", config.clone())
        .await
        .expect("Failed to create server");

    let client = AsyncUDP::new(client_key.clone(), "127.0.0.1:0", config)
        .await
        .expect("Failed to create client");

    let server_addr = server.local_addr().unwrap();
    let client_addr = client.local_addr().unwrap();

    println!("Server: {}", server_addr);
    println!("Client: {}", client_addr);

    // Set peer endpoints
    client.set_peer_endpoint(server_key.public, server_addr).await;
    server.set_peer_endpoint(client_key.public, client_addr).await;

    // Connect (handshake)
    println!("Connecting...");
    client
        .connect(&server_key.public)
        .await
        .expect("Connect failed");
    println!("Connected!");

    // Run benchmark
    run_benchmark(&client, &server, &server_key, size_mb).await;
}

async fn run_benchmark(
    client: &Arc<AsyncUDP>,
    server: &Arc<AsyncUDP>,
    server_key: &KeyPair,
    size_mb: usize,
) {
    let chunk_bytes = 1200usize;
    let iterations = (size_mb * 1024 * 1024) / chunk_bytes;
    let total_bytes = (iterations * chunk_bytes) as u64;

    println!("Sending {} MB ({} packets)...", size_mb, iterations);

    // Generate data
    let chunk: Vec<u8> = (0..chunk_bytes).map(|i| (i % 256) as u8).collect();

    // Counters
    let recv_bytes = Arc::new(AtomicU64::new(0));
    let recv_packets = Arc::new(AtomicU64::new(0));

    // Receiver task
    let server_clone = server.clone();
    let recv_bytes_clone = recv_bytes.clone();
    let recv_packets_clone = recv_packets.clone();
    let total_bytes_clone = total_bytes;

    let recv_handle = tokio::spawn(async move {
        while recv_bytes_clone.load(Ordering::Relaxed) < total_bytes_clone {
            match server_clone.read_from().await {
                Some(pkt) => {
                    let n = pkt.payload.len();
                    if n > 0 {
                        recv_bytes_clone.fetch_add(n as u64, Ordering::Relaxed);
                        recv_packets_clone.fetch_add(1, Ordering::Relaxed);
                    }
                }
                None => break,
            }
        }
    });

    // Sender
    let start = Instant::now();
    let mut sent_bytes = 0u64;

    for _ in 0..iterations {
        match client.write_to(&server_key.public, &chunk).await {
            Ok(_) => sent_bytes += chunk_bytes as u64,
            Err(e) => {
                eprintln!("Write failed: {:?}", e);
                break;
            }
        }
    }
    let send_time = start.elapsed();

    // Wait for receiver with timeout
    let timeout = Duration::from_secs(30);
    let wait_start = Instant::now();
    while recv_bytes.load(Ordering::Relaxed) < total_bytes && wait_start.elapsed() < timeout {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    if wait_start.elapsed() >= timeout {
        println!("Warning: Timeout");
    }

    let total_time = start.elapsed();

    // Results
    let final_recv_bytes = recv_bytes.load(Ordering::Relaxed);
    let final_recv_packets = recv_packets.load(Ordering::Relaxed);
    let loss = (iterations as f64 - final_recv_packets as f64) / iterations as f64 * 100.0;

    println!("=== Results ===");
    println!(
        "Sent:     {} packets, {:.2} MB",
        iterations,
        sent_bytes as f64 / 1024.0 / 1024.0
    );
    println!(
        "Received: {} packets, {:.2} MB",
        final_recv_packets,
        final_recv_bytes as f64 / 1024.0 / 1024.0
    );
    println!("Loss:     {:.2}%", loss);
    println!("Send time: {:?}", send_time);
    println!("Total time: {:?}", total_time);
    println!(
        "Throughput: {:.2} MB/s",
        final_recv_bytes as f64 / 1024.0 / 1024.0 / total_time.as_secs_f64()
    );

    // Cancel receiver task
    recv_handle.abort();
}
