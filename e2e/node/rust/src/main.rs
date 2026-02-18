//! Node SDK interoperability test between Rust, Go, and Zig.
//!
//! Each binary creates a Node, adds the peer, and based on role either
//! opens a stream (opener) or accepts one (accepter). Validates echo
//! round-trip and stream metadata.
//!
//! Usage:
//!   cargo run -- --name rust --config ../config.json

use std::env;
use std::fs;
use std::thread;
use std::time::Duration;

use zgrnet::node::{Node, NodeConfig, NodeStream, PeerConfig};
use zgrnet::noise::address::Address;
use zgrnet::noise::message::protocol;
use zgrnet::{Key, KeyPair};

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

    let my_host = config
        .hosts
        .iter()
        .find(|h| h.name == name)
        .unwrap_or_else(|| panic!("Host {} not found", name));

    let key_pair = key_from_hex(&my_host.private_key);
    println!("[{}] pubkey: {}...", name, hex::encode(&key_pair.public.as_bytes()[..8]));
    println!("[{}] role: {}", name, my_host.role);

    // Create Node.
    let node = Node::new(NodeConfig {
        key: key_pair.clone(),
        listen_port: my_host.port,
        allow_unknown: true,
    })
    .expect("create node");
    println!("[{}] listening on {}", name, node.local_addr());

    // Find peer.
    let peer_host = config
        .hosts
        .iter()
        .find(|h| h.name != name)
        .expect("no peer in config");

    let peer_kp = key_from_hex(&peer_host.private_key);
    let peer_endpoint = format!("127.0.0.1:{}", peer_host.port);
    node.add_peer(PeerConfig {
        public_key: peer_kp.public,
        endpoint: Some(peer_endpoint.clone()),
    })
    .expect("add peer");
    println!("[{}] added peer {} at {}", name, peer_host.name, peer_endpoint);

    if my_host.role == "opener" {
        thread::sleep(Duration::from_secs(2));
        run_opener(&node, &peer_kp.public, &peer_host.name, &config.test, name);
    } else {
        run_accepter(&node, &peer_kp.public, &peer_host.name, &config.test, name);
    }

    println!("[{}] test completed successfully!", name);
    node.stop();
}

fn run_opener(node: &Node, peer_pk: &Key, peer_name: &str, test: &TestConfig, _name: &str) {
    println!("[opener] connecting to {}...", peer_name);
    node.connect(peer_pk).expect("connect");
    println!("[opener] connected!");
    thread::sleep(Duration::from_millis(100));

    println!("[opener] dialing {}:8080...", peer_name);
    let stream = node.dial(peer_pk, 8080).expect("dial");
    println!(
        "[opener] stream opened: proto={}, remotePK={}...",
        stream.proto(),
        hex::encode(&stream.remote_pubkey().as_bytes()[..8])
    );

    assert_eq!(stream.proto(), protocol::TCP_PROXY, "proto mismatch");

    // Echo test.
    let msg = test.echo_message.as_bytes();
    stream.write(msg).expect("write");
    println!("[opener] sent: {:?}", test.echo_message);

    let mut buf = [0u8; 1024];
    let nr = read_timeout(&stream, &mut buf, Duration::from_secs(10));
    assert!(nr > 0, "read timeout");
    let response = std::str::from_utf8(&buf[..nr]).expect("utf8");
    println!("[opener] received: {:?}", response);

    let expected = format!("Echo from {}: {}", peer_name, test.echo_message);
    assert_eq!(response, expected, "echo mismatch");
    println!("[opener] PASS: echo verified");

    thread::sleep(Duration::from_millis(500));
    stream.close();
}

fn run_accepter(node: &Node, _peer_pk: &Key, _peer_name: &str, test: &TestConfig, name: &str) {
    println!("[accepter] waiting for stream...");

    let stream = node.accept_stream().expect("accept");
    println!(
        "[accepter] accepted stream: proto={}, remotePK={}...",
        stream.proto(),
        hex::encode(&stream.remote_pubkey().as_bytes()[..8])
    );

    assert_eq!(stream.proto(), protocol::TCP_PROXY, "proto mismatch");

    // Verify metadata.
    let (addr, _) = Address::decode(stream.metadata()).expect("decode address");
    assert_eq!(addr.host, "127.0.0.1", "addr host mismatch");
    assert_eq!(addr.port, 8080, "addr port mismatch");
    println!("[accepter] address verified: {}:{}", addr.host, addr.port);

    // Read echo.
    let mut buf = [0u8; 1024];
    let nr = read_timeout(&stream, &mut buf, Duration::from_secs(10));
    assert!(nr > 0, "read timeout");
    let received = std::str::from_utf8(&buf[..nr]).expect("utf8");
    println!("[accepter] received: {:?}", received);

    // Echo back.
    let reply = format!("Echo from {}: {}", name, received);
    stream.write(reply.as_bytes()).expect("write");
    println!("[accepter] sent: {:?}", reply);

    thread::sleep(Duration::from_millis(500));
    stream.close();
}

fn read_timeout(s: &NodeStream, buf: &mut [u8], timeout: Duration) -> usize {
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > timeout {
            return 0;
        }
        match s.read(buf) {
            Ok(0) => thread::sleep(Duration::from_millis(1)),
            Ok(n) => return n,
            Err(_) => return 0,
        }
    }
}

fn key_from_hex(hex_str: &str) -> KeyPair {
    let bytes = hex::decode(hex_str).expect("invalid hex");
    assert_eq!(bytes.len(), 32, "key must be 32 bytes");
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    KeyPair::from_private(Key::from(key))
}
