//! Host integration test with real TUN devices.
//!
//! Requires root/sudo to create TUN devices.
//!
//! Usage:
//!   cd zig && zig build -Doptimize=ReleaseFast
//!   cd rust && cargo build --features tun --example host_test
//!   sudo target/debug/examples/host_test

use std::process;

#[cfg(feature = "tun")]
use {
    zgrnet::noise::KeyPair,
    zgrnet::host::{Config, Host, TunDevice},
    zgrnet::tun,
    std::io,
    std::net::Ipv4Addr,
    std::process::Command,
    std::sync::Arc,
};

// Wrapper around tun::Device that implements TunDevice trait
#[cfg(feature = "tun")]
struct RealTun {
    dev: tun::Device,
}

#[cfg(feature = "tun")]
impl TunDevice for RealTun {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.dev.read_packet(buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.dev.write_packet(buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    fn close(&self) -> io::Result<()> {
        // Device is closed on drop
        Ok(())
    }
}

fn main() {
    #[cfg(not(feature = "tun"))]
    {
        eprintln!("ERROR: This test requires the 'tun' feature.");
        eprintln!("  cargo build --features tun --example host_test");
        process::exit(1);
    }

    #[cfg(feature = "tun")]
    run_test();
}

#[cfg(feature = "tun")]
fn run_test() {
    println!("=== Host TUN Integration Test (Rust) ===");
    println!();

    // Check root
    if unsafe { libc::getuid() } != 0 {
        eprintln!("ERROR: This test requires root privileges.");
        eprintln!("  sudo target/debug/examples/host_test");
        process::exit(1);
    }

    // Generate keypairs
    let key_a = KeyPair::generate();
    let key_b = KeyPair::generate();
    println!("Host A pubkey: {}", hex::encode(&key_a.public.0[..8]));
    println!("Host B pubkey: {}", hex::encode(&key_b.public.0[..8]));
    println!();

    // --- Create and configure TUN devices ---
    println!("[1/5] Creating TUN devices...");
    tun::init().expect("failed to init TUN");

    let tun_a = tun::Device::create(None).expect("failed to create TUN A");
    let tun_b = tun::Device::create(None).expect("failed to create TUN B");

    println!("  TUN A: {}", tun_a.name());
    println!("  TUN B: {}", tun_b.name());

    // Configure TUN A: 100.64.0.1/24
    tun_a.set_mtu(1400).expect("set MTU A");
    tun_a
        .set_ipv4(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
        )
        .expect("set IPv4 A");
    tun_a.up().expect("up A");
    println!("  TUN A: 100.64.0.1/24 UP");

    // Configure TUN B: 100.64.1.1/24
    tun_b.set_mtu(1400).expect("set MTU B");
    tun_b
        .set_ipv4(
            Ipv4Addr::new(100, 64, 1, 1),
            Ipv4Addr::new(255, 255, 255, 0),
        )
        .expect("set IPv4 B");
    tun_b.up().expect("up B");
    println!("  TUN B: 100.64.1.1/24 UP");
    println!();

    // --- Create Hosts ---
    println!("[2/5] Creating Hosts...");
    let host_a = Host::new(
        Config {
            private_key: key_a.clone(),
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            mtu: 1400,
            listen_port: 0,
            peers: vec![],
        },
        Arc::new(RealTun { dev: tun_a }),
    )
    .expect("create Host A");

    let host_b = Host::new(
        Config {
            private_key: key_b.clone(),
            tun_ipv4: Ipv4Addr::new(100, 64, 1, 1),
            mtu: 1400,
            listen_port: 0,
            peers: vec![],
        },
        Arc::new(RealTun { dev: tun_b }),
    )
    .expect("create Host B");

    let port_a = host_a.local_addr().port();
    let port_b = host_b.local_addr().port();
    println!("  Host A: UDP :{}", port_a);
    println!("  Host B: UDP :{}", port_b);

    // Add peers with static IPs
    host_a
        .add_peer_with_ip(
            key_b.public,
            &format!("127.0.0.1:{}", port_b),
            Ipv4Addr::new(100, 64, 0, 2),
        )
        .expect("add peer B on A");
    host_b
        .add_peer_with_ip(
            key_a.public,
            &format!("127.0.0.1:{}", port_a),
            Ipv4Addr::new(100, 64, 1, 2),
        )
        .expect("add peer A on B");

    println!("  Host A: peer B = 100.64.0.2");
    println!("  Host B: peer A = 100.64.1.2");
    println!();

    // --- Start forwarding ---
    println!("[3/5] Starting forwarding loops...");
    host_a.run();
    host_b.run();
    println!("  OK");
    println!();

    // --- Handshake ---
    println!("[4/5] Noise IK handshake (A -> B)...");
    host_a.connect(&key_b.public).expect("handshake failed");
    println!("  Handshake complete!");
    println!();

    // Small delay for routes to settle
    std::thread::sleep(std::time::Duration::from_millis(200));

    // --- Run tests ---
    println!("[5/5] Running tests...");
    println!();

    let mut passed = 0;
    let mut failed = 0;

    // Test 1: ping from A side to B (100.64.0.2)
    if run_ping_test("A->B", "100.64.0.2") {
        passed += 1;
    } else {
        failed += 1;
    }

    // Test 2: ping from B side to A (100.64.1.2)
    if run_ping_test("B->A", "100.64.1.2") {
        passed += 1;
    } else {
        failed += 1;
    }

    // Summary
    println!();
    println!("=== Results ===");
    println!("  Passed: {}", passed);
    println!("  Failed: {}", failed);
    println!();

    if failed > 0 {
        println!("SOME TESTS FAILED");
        process::exit(1);
    }
    println!("All tests passed!");
    // Exit immediately — close() would block because TUN read threads
    // can't be interrupted (RealTun::close is a no-op).
    // OS cleans up all resources on process exit.
    process::exit(0);
}

#[cfg(feature = "tun")]
fn run_ping_test(name: &str, target: &str) -> bool {
    println!("--- Test: {} (ping {}) ---", name, target);

    let output = Command::new("ping")
        .args(["-c", "3", "-W", "2", target])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let combined = format!("{}{}", stdout, stderr);

            for line in combined.trim().lines() {
                println!("  {}", line);
            }

            if !out.status.success() {
                println!("  RESULT: FAIL (exit code {:?})", out.status.code());
                return false;
            }

            if combined.contains("0.0% packet loss") || combined.contains(" 0% packet loss") {
                println!("  RESULT: PASS");
                true
            } else {
                println!("  RESULT: FAIL (packet loss)");
                false
            }
        }
        Err(e) => {
            println!("  RESULT: FAIL ({})", e);
            false
        }
    }
}

