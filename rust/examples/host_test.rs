//! Cross-language Host communication demo.
//!
//! Usage:
//!   cargo run --example host_test -- --name rust
//!
//! Or with Bazel:
//!   bazel run //rust:host_test_example -- --name rust

use std::env;
use std::fs;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use noise::keypair::{Key, KeyPair};
use noise::host::{Host, HostConfig, Message};
use noise::message::protocol;
use noise::udp_listener::UdpListener;
use noise::udp::UdpAddr;

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
        .expect("Usage: --name <name>");

    // Load config - try CONFIG_PATH env var first, then use path relative to crate manifest
    let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        std::path::Path::new(manifest_dir)
            .parent()
            .unwrap() // Move up to repo root from rust/
            .join("examples/host_test/config.json")
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

    // Create UDP transport
    let bind_addr = format!("0.0.0.0:{}", my_host.port);
    let transport = UdpListener::bind(&bind_addr)
        .unwrap_or_else(|e| panic!("Failed to bind: {}", e));

    println!("[{}] Listening on port {}", name, transport.port());

    // Create Host
    let mut host = Host::new(HostConfig {
        private_key: Some(key_pair.clone()),
        transport,
        mtu: Some(1280),
        allow_unknown_peers: true,
    }).unwrap();

    // Add other hosts as peers
    for h in &config.hosts {
        if h.name == name {
            continue;
        }

        let peer_priv_bytes = hex::decode(&h.private_key).unwrap();
        let mut peer_priv = [0u8; 32];
        peer_priv.copy_from_slice(&peer_priv_bytes);
        let peer_kp = KeyPair::from_private(Key::from(peer_priv));

        let addr = UdpAddr::parse(&format!("127.0.0.1:{}", h.port)).unwrap();
        host.add_peer(peer_kp.public, Some(Box::new(addr))).unwrap();
        println!("[{}] Added peer {} at port {}", name, h.name, h.port);
    }

    // Wait for other hosts to start
    println!("[{}] Waiting 2 seconds for other hosts...", name);
    thread::sleep(Duration::from_secs(2));

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
        match host.connect(&peer_kp.public) {
            Ok(()) => {
                println!("[{}] Connected to {}!", name, h.name);

                // Send test message
                let msg = format!("Hello from {} to {}!", name, h.name);
                if let Err(e) = host.send(&peer_kp.public, protocol::CHAT, msg.as_bytes()) {
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

    // Receive messages
    loop {
        match host.recv_timeout(Duration::from_secs(1)) {
            Ok(msg) => {
                let from_name = find_peer_name(&config, &msg.from);
                let data = String::from_utf8_lossy(&msg.data);
                println!("[{}] Received from {}: protocol={}, data={:?}",
                         name, from_name, msg.protocol, data);

                // Echo back if not already an ACK
                if !data.starts_with("ACK") {
                    let reply = format!("ACK from {}: {}", name, data);
                    let _ = host.send(&msg.from, msg.protocol, reply.as_bytes());
                }
            }
            Err(noise::host::HostError::Timeout) => {
                // Normal timeout, continue
            }
            Err(noise::host::HostError::Closed) => {
                println!("[{}] Host closed", name);
                break;
            }
            Err(e) => {
                eprintln!("[{}] Recv error: {}", name, e);
            }
        }
    }
}

fn find_peer_name(config: &Config, pubkey: &Key) -> String {
    for h in &config.hosts {
        if let Ok(priv_bytes) = hex::decode(&h.private_key) {
            if priv_bytes.len() == 32 {
                let mut priv_key = [0u8; 32];
                priv_key.copy_from_slice(&priv_bytes);
                let kp = KeyPair::from_private(Key::from(priv_key));
                if &kp.public == pubkey {
                    return h.name.clone();
                }
            }
        }
    }
    hex::encode(&pubkey.as_bytes()[..4]) + "..."
}
