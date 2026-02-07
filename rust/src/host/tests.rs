use super::*;
use crate::noise::KeyPair;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

// ============================================================================
// MockTUN
// ============================================================================

/// Simulates a TUN device using channels.
struct MockTUN {
    read_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    read_tx: mpsc::Sender<Vec<u8>>,
    write_tx: mpsc::Sender<Vec<u8>>,
    write_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    closed: AtomicBool,
}

impl MockTUN {
    fn new() -> Arc<Self> {
        let (read_tx, read_rx) = mpsc::channel();
        let (write_tx, write_rx) = mpsc::channel();
        Arc::new(Self {
            read_rx: Mutex::new(read_rx),
            read_tx,
            write_tx,
            write_rx: Mutex::new(write_rx),
            closed: AtomicBool::new(false),
        })
    }

    /// Inject a packet into the read side (simulating app traffic).
    fn inject(&self, pkt: Vec<u8>) {
        let _ = self.read_tx.send(pkt);
    }

    /// Receive a packet from the write side (capturing host output).
    fn receive(&self, timeout: Duration) -> Option<Vec<u8>> {
        let rx = self.write_rx.lock().unwrap();
        rx.recv_timeout(timeout).ok()
    }
}

impl TunDevice for MockTUN {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let rx = self.read_rx.lock().unwrap();
        // Use a short timeout so the loop can check closed state
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if self.closed.load(Ordering::SeqCst) {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
                } else {
                    // Return 0 to indicate no data, the loop will retry
                    Ok(0)
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "disconnected"))
            }
        }
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
        }
        let pkt = buf.to_vec();
        let _ = self.write_tx.send(pkt);
        Ok(buf.len())
    }

    fn close(&self) -> io::Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Creates an ICMP echo request/reply payload.
fn make_icmp_echo(typ: u8, code: u8, id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 8 + data.len()];
    pkt[0] = typ;
    pkt[1] = code;
    // checksum at [2:4] = 0 for now
    pkt[4] = (id >> 8) as u8;
    pkt[5] = id as u8;
    pkt[6] = (seq >> 8) as u8;
    pkt[7] = seq as u8;
    pkt[8..].copy_from_slice(data);

    // Compute ICMP checksum
    let cs = icmp_checksum(&pkt);
    pkt[2] = (cs >> 8) as u8;
    pkt[3] = cs as u8;
    pkt
}

/// Computes ICMP checksum (same as IP header checksum).
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !sum as u16
}

/// Creates a minimal TCP SYN segment.
fn make_tcp_syn(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 20];
    pkt[0] = (src_port >> 8) as u8;
    pkt[1] = src_port as u8;
    pkt[2] = (dst_port >> 8) as u8;
    pkt[3] = dst_port as u8;
    // seq = 1000
    pkt[4] = 0x00;
    pkt[5] = 0x00;
    pkt[6] = 0x03;
    pkt[7] = 0xE8;
    // ack = 0
    // data offset = 5 (20 bytes)
    pkt[12] = 0x50;
    // SYN flag
    pkt[13] = 0x02;
    // window = 65535
    pkt[14] = 0xFF;
    pkt[15] = 0xFF;
    // checksum [16:18] starts as 0, will be set by build_ipv4_packet
    pkt
}

// ============================================================================
// IPAllocator tests
// ============================================================================

#[test]
fn test_ipalloc_assign() {
    let alloc = IPAllocator::new();
    let key = KeyPair::generate();

    let ip = alloc.assign(key.public).unwrap();
    assert_eq!(ip, Ipv4Addr::new(100, 64, 0, 2));

    // Second call returns same IP
    let ip2 = alloc.assign(key.public).unwrap();
    assert_eq!(ip, ip2);

    // Different key gets next IP
    let key2 = KeyPair::generate();
    let ip3 = alloc.assign(key2.public).unwrap();
    assert_eq!(ip3, Ipv4Addr::new(100, 64, 0, 3));
}

#[test]
fn test_ipalloc_assign_static() {
    let alloc = IPAllocator::new();
    let key = KeyPair::generate();
    let ip = Ipv4Addr::new(100, 64, 1, 100);

    alloc.assign_static(key.public, ip).unwrap();

    assert_eq!(alloc.lookup_by_pubkey(&key.public), Some(ip));
    assert_eq!(alloc.lookup_by_ip(ip), Some(key.public));
}

#[test]
fn test_ipalloc_conflict() {
    let alloc = IPAllocator::new();
    let key1 = KeyPair::generate();
    let key2 = KeyPair::generate();
    let ip = Ipv4Addr::new(100, 64, 1, 100);

    alloc.assign_static(key1.public, ip).unwrap();
    assert!(alloc.assign_static(key2.public, ip).is_err());
}

#[test]
fn test_ipalloc_remove() {
    let alloc = IPAllocator::new();
    let key = KeyPair::generate();

    let ip = alloc.assign(key.public).unwrap();
    assert_eq!(alloc.count(), 1);

    alloc.remove(&key.public);
    assert_eq!(alloc.count(), 0);
    assert!(alloc.lookup_by_ip(ip).is_none());
    assert!(alloc.lookup_by_pubkey(&key.public).is_none());
}

#[test]
fn test_ipalloc_concurrent() {
    let alloc = Arc::new(IPAllocator::new());
    let mut handles = vec![];

    for _ in 0..10 {
        let alloc = Arc::clone(&alloc);
        handles.push(thread::spawn(move || {
            let key = KeyPair::generate();
            alloc.assign(key.public).unwrap()
        }));
    }

    let mut ips: Vec<Ipv4Addr> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    ips.sort();
    ips.dedup();
    assert_eq!(ips.len(), 10); // all unique
    assert_eq!(alloc.count(), 10);
}

// ============================================================================
// Host tests
// ============================================================================

#[test]
fn test_host_new() {
    let key = KeyPair::generate();
    let tun = MockTUN::new();

    let host = Host::new(
        Config {
            private_key: key.clone(),
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            mtu: 1400,
            listen_port: 0,
            peers: vec![],
        },
        tun,
    )
    .unwrap();

    assert_eq!(host.public_key(), key.public);
    let addr = host.local_addr();
    assert_ne!(addr.port(), 0);
    host.close();
}

#[test]
fn test_host_add_peer() {
    let key_a = KeyPair::generate();
    let key_b = KeyPair::generate();
    let tun = MockTUN::new();

    let host = Host::new(
        Config {
            private_key: key_a,
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            mtu: 1400,
            listen_port: 0,
            peers: vec![],
        },
        tun,
    )
    .unwrap();

    host.add_peer(key_b.public, "127.0.0.1:12345").unwrap();

    let ip = host.ip_alloc.lookup_by_pubkey(&key_b.public).unwrap();
    assert_eq!(ip, Ipv4Addr::new(100, 64, 0, 2));

    host.close();
}

#[test]
fn test_host_icmp_forwarding() {
    let key_a = KeyPair::generate();
    let key_b = KeyPair::generate();

    let tun_a = MockTUN::new();
    let tun_b = MockTUN::new();
    let tun_a_ref = Arc::clone(&tun_a);
    let tun_b_ref = Arc::clone(&tun_b);

    // Create Host A
    let host_a = Host::new(
        Config {
            private_key: key_a.clone(),
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            mtu: 1400,
            listen_port: 0,
            peers: vec![],
        },
        tun_a,
    )
    .unwrap();

    // Create Host B
    let host_b = Host::new(
        Config {
            private_key: key_b.clone(),
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            mtu: 1400,
            listen_port: 0,
            peers: vec![],
        },
        tun_b,
    )
    .unwrap();

    // Add peers using actual ports
    let port_a = host_a.local_addr().port();
    let port_b = host_b.local_addr().port();

    host_a
        .add_peer(key_b.public, &format!("127.0.0.1:{}", port_b))
        .unwrap();
    host_b
        .add_peer(key_a.public, &format!("127.0.0.1:{}", port_a))
        .unwrap();

    let ip_b_on_a = host_a.ip_alloc.lookup_by_pubkey(&key_b.public).unwrap();

    // Start forwarding
    host_a.run();
    host_b.run();

    // Handshake
    host_a.connect(&key_b.public).unwrap();
    thread::sleep(Duration::from_millis(50));

    // Build ICMP echo request: A -> B
    let icmp_payload = make_icmp_echo(8, 0, 1, 1, b"ping");
    let ip_pkt = build_ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 1),
        ip_b_on_a,
        1,
        &icmp_payload,
    )
    .unwrap();

    // Inject into TUN A
    tun_a_ref.inject(ip_pkt);

    // Wait for packet at TUN B
    let received = tun_b_ref
        .receive(Duration::from_secs(3))
        .expect("timeout waiting for ICMP at Host B");

    let info = parse_ip_packet(&received).unwrap();
    assert_eq!(info.version, 4);
    assert_eq!(info.protocol, 1); // ICMP
    assert_eq!(info.dst_ip, &[100, 64, 0, 1]); // B's TUN IP
    assert!(info.payload.len() >= 8);
    assert_eq!(info.payload[0], 8); // ICMP Echo Request type

    host_a.close();
    host_b.close();
}

#[test]
fn test_host_tcp_forwarding() {
    let key_a = KeyPair::generate();
    let key_b = KeyPair::generate();

    let tun_a = MockTUN::new();
    let tun_b = MockTUN::new();
    let tun_a_ref = Arc::clone(&tun_a);
    let tun_b_ref = Arc::clone(&tun_b);

    let host_a = Host::new(
        Config {
            private_key: key_a.clone(),
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            mtu: 1400,
            listen_port: 0,
            peers: vec![],
        },
        tun_a,
    )
    .unwrap();

    let host_b = Host::new(
        Config {
            private_key: key_b.clone(),
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            mtu: 1400,
            listen_port: 0,
            peers: vec![],
        },
        tun_b,
    )
    .unwrap();

    let port_a = host_a.local_addr().port();
    let port_b = host_b.local_addr().port();

    host_a
        .add_peer(key_b.public, &format!("127.0.0.1:{}", port_b))
        .unwrap();
    host_b
        .add_peer(key_a.public, &format!("127.0.0.1:{}", port_a))
        .unwrap();

    let ip_b_on_a = host_a.ip_alloc.lookup_by_pubkey(&key_b.public).unwrap();

    host_a.run();
    host_b.run();

    host_a.connect(&key_b.public).unwrap();
    thread::sleep(Duration::from_millis(50));

    // Build TCP SYN packet
    let tcp_payload = make_tcp_syn(12345, 80);
    let ip_pkt = build_ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 1),
        ip_b_on_a,
        6,
        &tcp_payload,
    )
    .unwrap();

    tun_a_ref.inject(ip_pkt);

    let received = tun_b_ref
        .receive(Duration::from_secs(3))
        .expect("timeout waiting for TCP at Host B");

    let info = parse_ip_packet(&received).unwrap();
    assert_eq!(info.protocol, 6); // TCP

    // Verify TCP checksum is valid after rebuild
    let tcp_data = info.payload;
    let mut sum: u32 = 0;
    // Pseudo-header
    sum += ((info.src_ip[0] as u32) << 8) | (info.src_ip[1] as u32);
    sum += ((info.src_ip[2] as u32) << 8) | (info.src_ip[3] as u32);
    sum += ((info.dst_ip[0] as u32) << 8) | (info.dst_ip[1] as u32);
    sum += ((info.dst_ip[2] as u32) << 8) | (info.dst_ip[3] as u32);
    sum += 6u32; // TCP protocol
    sum += tcp_data.len() as u32;
    // Data
    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += ((tcp_data[i] as u32) << 8) | (tcp_data[i + 1] as u32);
        i += 2;
    }
    if tcp_data.len() % 2 == 1 {
        sum += (tcp_data[tcp_data.len() - 1] as u32) << 8;
    }
    while sum > 0xFFFF {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    let cs = !sum as u16;
    assert_eq!(cs, 0, "TCP checksum invalid after forwarding: 0x{:04x}", cs);

    host_a.close();
    host_b.close();
}

#[test]
fn test_host_bidirectional() {
    let key_a = KeyPair::generate();
    let key_b = KeyPair::generate();

    let tun_a = MockTUN::new();
    let tun_b = MockTUN::new();
    let tun_a_ref = Arc::clone(&tun_a);
    let tun_b_ref = Arc::clone(&tun_b);

    let host_a = Host::new(
        Config {
            private_key: key_a.clone(),
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            mtu: 1400,
            listen_port: 0,
            peers: vec![],
        },
        tun_a,
    )
    .unwrap();

    let host_b = Host::new(
        Config {
            private_key: key_b.clone(),
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            mtu: 1400,
            listen_port: 0,
            peers: vec![],
        },
        tun_b,
    )
    .unwrap();

    let port_a = host_a.local_addr().port();
    let port_b = host_b.local_addr().port();

    host_a
        .add_peer(key_b.public, &format!("127.0.0.1:{}", port_b))
        .unwrap();
    host_b
        .add_peer(key_a.public, &format!("127.0.0.1:{}", port_a))
        .unwrap();

    let ip_b_on_a = host_a.ip_alloc.lookup_by_pubkey(&key_b.public).unwrap();
    let ip_a_on_b = host_b.ip_alloc.lookup_by_pubkey(&key_a.public).unwrap();

    host_a.run();
    host_b.run();

    host_a.connect(&key_b.public).unwrap();
    thread::sleep(Duration::from_millis(50));

    // A -> B
    let icmp_req = make_icmp_echo(8, 0, 1, 1, b"ping");
    let pkt_a_to_b = build_ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 1),
        ip_b_on_a,
        1,
        &icmp_req,
    )
    .unwrap();
    tun_a_ref.inject(pkt_a_to_b);

    assert!(
        tun_b_ref.receive(Duration::from_secs(3)).is_some(),
        "A->B: timeout"
    );

    // B -> A
    let icmp_reply = make_icmp_echo(0, 0, 1, 1, b"pong");
    let pkt_b_to_a = build_ipv4_packet(
        Ipv4Addr::new(100, 64, 0, 1),
        ip_a_on_b,
        1,
        &icmp_reply,
    )
    .unwrap();
    tun_b_ref.inject(pkt_b_to_a);

    let received = tun_a_ref
        .receive(Duration::from_secs(3))
        .expect("B->A: timeout");

    let info = parse_ip_packet(&received).unwrap();
    assert_eq!(info.protocol, 1); // ICMP

    host_a.close();
    host_b.close();
}

#[test]
fn test_host_close() {
    let key = KeyPair::generate();
    let tun = MockTUN::new();

    let host = Host::new(
        Config {
            private_key: key,
            tun_ipv4: Ipv4Addr::new(100, 64, 0, 1),
            mtu: 1400,
            listen_port: 0,
            peers: vec![],
        },
        tun,
    )
    .unwrap();

    host.run();
    thread::sleep(Duration::from_millis(50));

    // Close should stop the background threads
    host.close();

    // Double close should not panic
    host.close();
}
