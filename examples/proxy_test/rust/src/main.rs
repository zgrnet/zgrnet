//! Cross-language proxy interop test.
//!
//! Two roles:
//!   handler: echo TCP server + TCP_PROXY(69) KCP handler
//!   proxy:   opens KCP stream(proto=69) through tunnel, verifies echo
//!
//! Usage:
//!   cargo run -- --name handler --config ../config.json
//!   cargo run -- --name proxy   --config ../config.json

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use zgrnet::noise::address::Address;
use zgrnet::noise::message::protocol;
use zgrnet::{Key, KeyPair, Stream, UDP, UdpOptions};

#[derive(serde::Deserialize)]
struct Config {
    hosts: Vec<HostInfo>,
    echo_port: u16,
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
    message: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let name = get_arg(&args, "--name");
    let config_path = get_arg(&args, "--config");

    let config: Config = serde_json::from_str(
        &fs::read_to_string(&config_path).expect("read config"),
    )
    .expect("parse config");

    let my_host = config.hosts.iter().find(|h| h.name == name).expect("host not found");
    let key_pair = load_key(&my_host.private_key);

    println!("[{}] role={} port={}", name, my_host.role, my_host.port);

    match my_host.role.as_str() {
        "handler" => run_handler(&config, my_host, key_pair),
        "proxy" => run_proxy(&config, my_host, key_pair),
        r => panic!("Unknown role: {}", r),
    }
}

fn run_handler(config: &Config, my_host: &HostInfo, key_pair: KeyPair) {
    // 1. Start echo server
    let echo_addr = format!("127.0.0.1:{}", config.echo_port);
    let echo_ln = TcpListener::bind(&echo_addr).expect("bind echo");
    println!("[handler] Echo on {}", echo_addr);

    thread::spawn(move || {
        for conn in echo_ln.incoming() {
            if let Ok(mut stream) = conn {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) => return,
                            Ok(n) => { let _ = stream.write_all(&buf[..n]); }
                            Err(_) => return,
                        }
                    }
                });
            }
        }
    });

    // 2. Create UDP
    let bind = format!("0.0.0.0:{}", my_host.port);
    let udp = Arc::new(
        UDP::new(key_pair, UdpOptions::new().bind_addr(&bind).allow_unknown(true)).expect("UDP"),
    );
    println!("[handler] UDP on {}", udp.host_info().addr);

    // Background consumer
    let udp2 = Arc::clone(&udp);
    thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        loop {
            if udp2.is_closed() { return; }
            let _ = udp2.read_from(&mut buf);
        }
    });

    // 3. Find proxy peer
    let peer = config.hosts.iter().find(|h| h.role == "proxy").expect("proxy host");
    let peer_kp = load_key(&peer.private_key);
    let endpoint: SocketAddr = format!("127.0.0.1:{}", peer.port).parse().unwrap();
    udp.set_peer_endpoint(peer_kp.public, endpoint);

    // 4. Accept stream
    println!("[handler] Waiting for TCP_PROXY stream...");
    let stream = udp.accept_stream(peer_kp.public).expect("accept stream");
    println!(
        "[handler] Got stream id={} proto={} metadata={}B",
        stream.id(),
        stream.proto(),
        stream.metadata().len()
    );

    assert_eq!(stream.proto(), protocol::TCP_PROXY, "expected proto=69");

    // 5. Handle: decode address → dial echo → relay
    let (addr, _) = Address::decode(stream.metadata()).expect("decode address");
    let target = format!("{}:{}", addr.host, addr.port);
    println!("[handler] Connecting to target: {}", target);
    let mut tcp = TcpStream::connect(&target).expect("connect target");
    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();

    // Relay: stream ↔ tcp
    let stream = Arc::new(stream);
    let stream2 = Arc::clone(&stream);
    let mut tcp2 = tcp.try_clone().expect("clone tcp");

    // stream → tcp
    let h1 = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            let n = blocking_read(&stream2, &mut buf);
            if n == 0 { return; }
            if tcp2.write_all(&buf[..n]).is_err() { return; }
        }
    });

    // tcp → stream
    let h2 = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match tcp.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => { if stream.write(&buf[..n]).is_err() { return; } }
                Err(_) => return,
            }
        }
    });

    h1.join().ok();
    h2.join().ok();
    println!("[handler] Done!");
}

fn run_proxy(config: &Config, my_host: &HostInfo, key_pair: KeyPair) {
    // 1. Create UDP
    let bind = format!("0.0.0.0:{}", my_host.port);
    let udp = Arc::new(
        UDP::new(key_pair, UdpOptions::new().bind_addr(&bind).allow_unknown(true)).expect("UDP"),
    );
    println!("[proxy] UDP on {}", udp.host_info().addr);

    // Background consumer
    let udp2 = Arc::clone(&udp);
    thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        loop {
            if udp2.is_closed() { return; }
            let _ = udp2.read_from(&mut buf);
        }
    });

    // 2. Connect to handler
    let handler = config.hosts.iter().find(|h| h.role == "handler").expect("handler host");
    let handler_kp = load_key(&handler.private_key);
    let endpoint: SocketAddr = format!("127.0.0.1:{}", handler.port).parse().unwrap();
    udp.set_peer_endpoint(handler_kp.public, endpoint);

    println!("[proxy] Connecting to handler...");
    udp.connect(handler_kp.public).expect("connect");
    println!("[proxy] Connected!");
    thread::sleep(Duration::from_millis(200));

    // 3. Open stream with proto=69 targeting echo server
    let addr = Address::ipv4("127.0.0.1", config.echo_port);
    let metadata = addr.encode().expect("encode address");
    println!(
        "[proxy] Opening stream proto={} target=127.0.0.1:{}",
        protocol::TCP_PROXY, config.echo_port
    );

    let stream = udp
        .open_stream(handler_kp.public, protocol::TCP_PROXY, &metadata)
        .expect("open stream");
    println!("[proxy] Stream opened id={}", stream.id());
    thread::sleep(Duration::from_millis(500));

    // 4. Send test data and verify echo
    let msg = config.test.message.as_bytes();
    println!("[proxy] Sending: {:?}", config.test.message);
    stream.write(msg).expect("write");

    let mut buf = vec![0u8; msg.len()];
    let mut total = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while total < msg.len() {
        if std::time::Instant::now() > deadline {
            panic!("[proxy] FAIL: timeout reading echo");
        }
        let n = blocking_read(&stream, &mut buf[total..]);
        total += n;
    }

    let got = &buf[..total];
    assert_eq!(got, msg, "[proxy] FAIL: echo mismatch");
    println!("[proxy] Echo verified: {:?}", std::str::from_utf8(got).unwrap());
    println!("[proxy] PASS!");
}

/// Blocking read from KCP stream (polls with short sleep).
fn blocking_read(stream: &Stream, buf: &mut [u8]) -> usize {
    loop {
        match stream.read(buf) {
            Ok(n) if n > 0 => return n,
            Ok(_) => thread::sleep(Duration::from_millis(1)),
            Err(_) => return 0,
        }
    }
}

fn get_arg(args: &[String], flag: &str) -> String {
    args.iter()
        .position(|x| x == flag)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.to_string())
        .unwrap_or_else(|| panic!("Missing flag: {}", flag))
}

fn load_key(hex_key: &str) -> KeyPair {
    let bytes = hex::decode(hex_key).expect("decode hex key");
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    KeyPair::from_private(Key::from(key))
}
