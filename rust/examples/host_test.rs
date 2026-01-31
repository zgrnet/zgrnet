//! Cross-language UDP communication demo.
//!
//! Usage:
//!   cargo run --example host_test -- --name rust
//!
//! Or with Bazel:
//!   bazel run //rust:host_test_example -- --name rust

use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use zgrnet::{Key, KeyPair};
use zgrnet::{UDP, UdpOptions, UdpError};

#[derive(serde::Deserialize)]
struct Config {
    hosts: Vec<HostInfo>,
}

#[derive(serde::Deserialize)]
struct HostInfo {
    name: String,
    private_key: String,
    port: u16,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let name = args
        .iter()
        .position(|x| x == "--name")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .expect("Usage: --name <name> --config <path>");

    // Load config - try --config flag first, then CONFIG_PATH env var, then default path
    let config_path = args
        .iter()
        .position(|x| x == "--config")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.to_string())
        .or_else(|| env::var("CONFIG_PATH").ok())
        .unwrap_or_else(|| {
            let manifest_dir = env!("CARGO_MANIFEST_DIR");
            std::path::Path::new(manifest_dir)
                .parent()
                .unwrap() // Move up to repo root from rust/
                .join("examples/net_test/config.json")
                .to_string_lossy()
                .to_string()
        });
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

    println!("[{}] Public key: {}", name, hex::encode(key_pair.public.as_bytes()));

    // Pre-calculate peer name map for efficient lookups
    let peer_names = build_peer_name_map(&config);

    // Create UDP
    let bind_addr = format!("0.0.0.0:{}", my_host.port);
    let udp = Arc::new(UDP::new(
        key_pair.clone(),
        UdpOptions::new().bind_addr(&bind_addr).allow_unknown(true),
    ).unwrap_or_else(|e| panic!("Failed to create UDP: {}", e)));

    let info = udp.host_info();
    println!("[{}] Listening on {}", name, info.addr);

    // Add other hosts as peers
    for h in &config.hosts {
        if h.name == name {
            continue;
        }

        let peer_priv_bytes = hex::decode(&h.private_key).unwrap();
        let mut peer_priv = [0u8; 32];
        peer_priv.copy_from_slice(&peer_priv_bytes);
        let peer_kp = KeyPair::from_private(Key::from(peer_priv));

        let endpoint: SocketAddr = format!("127.0.0.1:{}", h.port).parse().unwrap();
        udp.set_peer_endpoint(peer_kp.public, endpoint);
        println!("[{}] Added peer {} at port {}", name, h.name, h.port);
    }

    // Wait for other hosts to start
    println!("[{}] Waiting 2 seconds for other hosts...", name);
    thread::sleep(Duration::from_secs(2));

    // Start receive loop in background
    let udp_recv = Arc::clone(&udp);
    let recv_name = name.to_string();
    let peer_names_clone = peer_names.clone();
    let recv_handle = thread::spawn(move || {
        let mut buf = vec![0u8; 4096];
        loop {
            if udp_recv.is_closed() {
                break;
            }
            match udp_recv.read_from(&mut buf) {
                Ok((from_pk, n)) => {
                    let from_name = peer_names_clone.get(&from_pk)
                        .cloned()
                        .unwrap_or_else(|| hex::encode(&from_pk.as_bytes()[..4]) + "...");
                    let data = String::from_utf8_lossy(&buf[..n]);
                    println!("[{}] Received from {}: {:?}", recv_name, from_name, data);

                    // Echo back if not already an ACK
                    if !data.starts_with("ACK") {
                        let reply = format!("ACK from {}: {}", recv_name, data);
                        let _ = udp_recv.write_to(&from_pk, reply.as_bytes());
                    }
                }
                Err(UdpError::Closed) => {
                    println!("[{}] UDP closed", recv_name);
                    break;
                }
                Err(_) => {
                    // Timeout or other error, continue
                }
            }
        }
    });

    // Connect to and message other hosts
    for h in &config.hosts {
        if h.name == name {
            continue;
        }

        let peer_priv_bytes = hex::decode(&h.private_key).unwrap();
        let mut peer_priv = [0u8; 32];
        peer_priv.copy_from_slice(&peer_priv_bytes);
        let peer_kp = KeyPair::from_private(Key::from(peer_priv));

        println!("[{}] Connecting to {}...", name, h.name);
        match udp.connect(&peer_kp.public) {
            Ok(()) => {
                println!("[{}] Connected to {}!", name, h.name);

                // Send test message
                let msg = format!("Hello from {} to {}!", name, h.name);
                if let Err(e) = udp.write_to(&peer_kp.public, msg.as_bytes()) {
                    println!("[{}] Failed to send to {}: {}", name, h.name, e);
                } else {
                    println!("[{}] Sent message to {}", name, h.name);
                }
            }
            Err(e) => {
                println!("[{}] Failed to connect to {}: {}", name, h.name, e);
            }
        }
    }

    println!("[{}] Running... Press Ctrl+C to exit", name);

    // Wait a bit for messages then exit
    thread::sleep(Duration::from_secs(5));
    udp.close().unwrap();
    let _ = recv_handle.join();
}

/// Build a map of public keys to host names for efficient lookups.
fn build_peer_name_map(config: &Config) -> HashMap<Key, String> {
    let mut map = HashMap::new();
    for h in &config.hosts {
        if let Ok(priv_bytes) = hex::decode(&h.private_key) {
            if priv_bytes.len() == 32 {
                let mut priv_key = [0u8; 32];
                priv_key.copy_from_slice(&priv_bytes);
                let kp = KeyPair::from_private(Key::from(priv_key));
                map.insert(kp.public, h.name.clone());
            }
        }
    }
    map
}
