//! Node.Listen interop test binary (Rust).
//!
//! Tests proto-specific stream routing across languages.
//! The "opener" sends streams with two different protos (128=chat, 200=file).
//! The "accepter" uses listen(128) for chat and accept_stream for file.

use std::env;
use std::fs;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use zgrnet::node::{Node, NodeConfig, NodeStream, PeerConfig};
use zgrnet::{Key, KeyPair};

const PROTO_CHAT: u8 = 128;
const PROTO_FILE: u8 = 200;

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
        .unwrap_or_else(|e| panic!("read config {}: {}", config_path, e));
    let config: Config = serde_json::from_str(&config_data)
        .unwrap_or_else(|e| panic!("parse config: {}", e));

    let my_host = config
        .hosts
        .iter()
        .find(|h| h.name == name)
        .unwrap_or_else(|| panic!("host {} not found", name));

    let peer_host = config
        .hosts
        .iter()
        .find(|h| h.name != name)
        .expect("no peer in config");

    let key_pair = key_from_hex(&my_host.private_key);
    println!("[{}] role: {}", name, my_host.role);

    let node = Node::new(NodeConfig {
        key: key_pair.clone(),
        listen_port: my_host.port,
        allow_unknown: true,
    })
    .expect("create node");
    println!("[{}] listening on {}", name, node.local_addr());

    let peer_kp = key_from_hex(&peer_host.private_key);
    node.add_peer(PeerConfig {
        public_key: peer_kp.public,
        endpoint: Some(format!("127.0.0.1:{}", peer_host.port)),
    })
    .expect("add peer");

    if my_host.role == "opener" {
        thread::sleep(Duration::from_secs(2));
        run_opener(&node, &peer_kp.public, &config.test);
    } else {
        run_accepter(&node, &config.test, name);
    }

    println!("[{}] test completed successfully!", name);
    node.stop();
}

fn run_opener(node: &Node, peer_pk: &Key, test: &TestConfig) {
    println!("[opener] connecting...");
    node.connect(peer_pk).expect("connect");
    thread::sleep(Duration::from_millis(100));

    // Send chat stream (proto=128).
    let chat_stream = node
        .open_stream(peer_pk, PROTO_CHAT, b"chat-meta")
        .expect("open chat stream");

    // Send file stream (proto=200).
    let file_stream = node
        .open_stream(peer_pk, PROTO_FILE, b"file-meta")
        .expect("open file stream");

    // Echo test on chat.
    chat_stream.write(test.echo_message.as_bytes()).unwrap();
    println!("[opener] sent chat: {:?}", test.echo_message);

    let mut buf = [0u8; 1024];
    let nr = read_timeout(&chat_stream, &mut buf, Duration::from_secs(10));
    assert!(nr > 0, "chat read timeout");
    let response = std::str::from_utf8(&buf[..nr]).unwrap();
    let expected = format!("chat-echo: {}", test.echo_message);
    assert_eq!(response, expected, "chat echo mismatch");
    println!("[opener] PASS: chat echo verified");

    // Echo test on file.
    file_stream.write(b"file-data").unwrap();
    println!("[opener] sent file: \"file-data\"");

    let nr = read_timeout(&file_stream, &mut buf, Duration::from_secs(10));
    assert!(nr > 0, "file read timeout");
    let response = std::str::from_utf8(&buf[..nr]).unwrap();
    assert_eq!(response, "file-echo: file-data", "file echo mismatch");
    println!("[opener] PASS: file echo verified");

    thread::sleep(Duration::from_millis(500));
    chat_stream.close();
    file_stream.close();
}

fn run_accepter(node: &Arc<Node>, test: &TestConfig, _name: &str) {
    // Register listener for proto=128 (chat).
    let chat_ln = node.listen(PROTO_CHAT).expect("listen(chat)");
    println!("[accepter] listening on proto={} (chat)", PROTO_CHAT);

    // Accept chat via listen.
    let chat_handle = thread::spawn({
        let msg = test.echo_message.clone();
        move || {
            let stream = chat_ln.accept().expect("chat accept");
            assert_eq!(stream.proto(), PROTO_CHAT, "chat proto mismatch");
            println!("[accepter] accepted chat stream (proto={})", stream.proto());

            let mut buf = [0u8; 1024];
            let nr = read_timeout(&stream, &mut buf, Duration::from_secs(10));
            assert!(nr > 0, "chat read timeout");
            let received = std::str::from_utf8(&buf[..nr]).unwrap();
            println!("[accepter] chat received: {:?}", received);

            let reply = format!("chat-echo: {}", received);
            stream.write(reply.as_bytes()).unwrap();
            println!("[accepter] chat sent: {:?}", reply);
            thread::sleep(Duration::from_millis(200));
            stream.close();
            assert_eq!(received, msg, "chat message mismatch");
        }
    });

    // Accept file via accept_stream (no listener for proto=200).
    let node_clone = Arc::clone(node);
    let file_handle = thread::spawn(move || {
        let stream = node_clone.accept_stream().expect("accept_stream");
        assert_eq!(stream.proto(), PROTO_FILE, "file proto mismatch");
        println!("[accepter] accepted file stream (proto={})", stream.proto());

        let mut buf = [0u8; 1024];
        let nr = read_timeout(&stream, &mut buf, Duration::from_secs(10));
        assert!(nr > 0, "file read timeout");
        let received = std::str::from_utf8(&buf[..nr]).unwrap();
        println!("[accepter] file received: {:?}", received);

        let reply = format!("file-echo: {}", received);
        stream.write(reply.as_bytes()).unwrap();
        println!("[accepter] file sent: {:?}", reply);
        thread::sleep(Duration::from_millis(200));
        stream.close();
    });

    chat_handle.join().unwrap();
    file_handle.join().unwrap();
    thread::sleep(Duration::from_millis(500));
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
