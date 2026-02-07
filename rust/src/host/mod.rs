//! Host: bridges TUN virtual network device with encrypted UDP transport.
//!
//! The Host reads IP packets from a TUN device, strips the IP header,
//! encrypts the payload using the Noise Protocol, and sends it via UDP.
//! Incoming encrypted packets are decrypted, reassembled with a new IP header,
//! and written to the TUN device.
//!
//! # Architecture
//!
//! ```text
//! Outbound: TUN.Read -> parse dst IP -> lookup peer -> strip IP header -> encrypt -> UDP send
//! Inbound:  UDP recv -> decrypt -> lookup src IP -> rebuild IP header -> TUN.Write
//! ```

mod ipalloc;
mod packet;

pub use ipalloc::IPAllocator;
pub use packet::{PacketInfo, parse_ip_packet, build_ipv4_packet, build_ipv6_packet};

use crate::noise::{Key, KeyPair, message};
use crate::net::{UDP, UdpOptions};

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::collections::HashMap;

// ============================================================================
// TunDevice trait
// ============================================================================

/// Abstraction over a TUN device for reading/writing IP packets.
/// The real `tun::Device` satisfies this trait.
/// For testing, a mock implementation can be provided.
pub trait TunDevice: Send + Sync {
    /// Read an IP packet from the TUN device.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Write an IP packet to the TUN device.
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
    /// Close the TUN device.
    fn close(&self) -> io::Result<()>;
}

// ============================================================================
// Config
// ============================================================================

/// Configuration for creating a Host.
pub struct Config {
    /// Local keypair for Noise Protocol handshakes.
    pub private_key: KeyPair,
    /// Local IPv4 address assigned to the TUN device (CGNAT range).
    pub tun_ipv4: Ipv4Addr,
    /// Maximum Transmission Unit. Default: 1400 if zero.
    pub mtu: usize,
    /// UDP port to listen on. 0 for random.
    pub listen_port: u16,
    /// Initial peers.
    pub peers: Vec<PeerConfig>,
}

/// Configuration for a peer.
pub struct PeerConfig {
    /// Peer's Curve25519 public key.
    pub public_key: Key,
    /// Peer's UDP address in "host:port" format. Empty = no known endpoint.
    pub endpoint: String,
    /// Optional static IPv4 assignment. None = auto-allocate.
    pub ipv4: Option<Ipv4Addr>,
}

// ============================================================================
// Host
// ============================================================================

/// Host bridges a TUN virtual network device with encrypted UDP transport.
///
/// It routes IP packets between the TUN device and remote peers using the
/// Noise Protocol for encryption.
pub struct Host {
    tun: Arc<dyn TunDevice>,
    udp: Arc<UDP>,
    ip_alloc: Arc<IPAllocator>,
    tun_ipv4: Ipv4Addr,
    mtu: usize,
    closed: Arc<AtomicBool>,
    peers: RwLock<HashMap<Key, PeerConfig>>,
    threads: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl Host {
    /// Creates a new Host with the given configuration and TUN device.
    ///
    /// The caller is responsible for creating and configuring the TUN device
    /// (IP address, MTU, bringing it up) before passing it to `new`.
    pub fn new(cfg: Config, tun: Arc<dyn TunDevice>) -> Result<Arc<Self>, String> {
        let mtu = if cfg.mtu == 0 { 1400 } else { cfg.mtu };

        // Create UDP transport
        let bind_addr = format!("0.0.0.0:{}", cfg.listen_port);
        let udp = UDP::new(
            cfg.private_key,
            UdpOptions::new()
                .bind_addr(&bind_addr)
                .allow_unknown(true),
        )
        .map_err(|e| format!("host: create UDP failed: {}", e))?;

        let host = Arc::new(Self {
            tun,
            udp: Arc::new(udp),
            ip_alloc: Arc::new(IPAllocator::new()),
            tun_ipv4: cfg.tun_ipv4,
            mtu,
            closed: Arc::new(AtomicBool::new(false)),
            peers: RwLock::new(HashMap::new()),
            threads: Mutex::new(Vec::new()),
        });

        // Register initial peers
        for p in &cfg.peers {
            host.add_peer_internal(p)?;
        }

        Ok(host)
    }

    /// Adds a peer with auto-allocated IPv4.
    pub fn add_peer(&self, pk: Key, endpoint: &str) -> Result<(), String> {
        let cfg = PeerConfig {
            public_key: pk,
            endpoint: endpoint.to_string(),
            ipv4: None,
        };
        self.add_peer_internal(&cfg)
    }

    /// Adds a peer with a specific static IPv4 address.
    pub fn add_peer_with_ip(
        &self,
        pk: Key,
        endpoint: &str,
        ipv4: Ipv4Addr,
    ) -> Result<(), String> {
        let cfg = PeerConfig {
            public_key: pk,
            endpoint: endpoint.to_string(),
            ipv4: Some(ipv4),
        };
        self.add_peer_internal(&cfg)
    }

    fn add_peer_internal(&self, p: &PeerConfig) -> Result<(), String> {
        // Assign IP
        if let Some(ipv4) = p.ipv4 {
            self.ip_alloc
                .assign_static(p.public_key, ipv4)
                .map_err(|e| format!("host: assign static IP: {}", e))?;
        } else {
            self.ip_alloc
                .assign(p.public_key)
                .map_err(|e| format!("host: assign IP: {}", e))?;
        }

        // Set endpoint in UDP layer
        if !p.endpoint.is_empty() {
            let addr: SocketAddr = p
                .endpoint
                .parse()
                .map_err(|e| format!("host: resolve endpoint {:?}: {}", p.endpoint, e))?;
            self.udp.set_peer_endpoint(p.public_key, addr);
        }

        // Store peer config
        let mut peers = self.peers.write().unwrap();
        peers.insert(
            p.public_key,
            PeerConfig {
                public_key: p.public_key,
                endpoint: p.endpoint.clone(),
                ipv4: p.ipv4,
            },
        );

        Ok(())
    }

    /// Initiates a Noise handshake with the specified peer.
    pub fn connect(&self, pk: &Key) -> Result<(), String> {
        self.udp
            .connect(pk)
            .map_err(|e| format!("host: connect: {}", e))
    }

    /// Starts the outbound and inbound forwarding loops in background threads.
    pub fn run(self: &Arc<Self>) {
        let host_out = Arc::clone(self);
        let host_in = Arc::clone(self);

        let mut threads = self.threads.lock().unwrap();

        threads.push(
            thread::Builder::new()
                .name("host-outbound".into())
                .spawn(move || host_out.outbound_loop())
                .expect("failed to spawn outbound thread"),
        );

        threads.push(
            thread::Builder::new()
                .name("host-inbound".into())
                .spawn(move || host_in.inbound_loop())
                .expect("failed to spawn inbound thread"),
        );
    }

    /// Gracefully shuts down the host.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return; // already closed
        }

        // Close TUN and UDP to unblock the loops
        let _ = self.tun.close();
        let _ = self.udp.close();

        // Wait for threads to finish
        let mut threads = self.threads.lock().unwrap();
        for t in threads.drain(..) {
            let _ = t.join();
        }
    }

    /// Returns the local UDP address.
    pub fn local_addr(&self) -> SocketAddr {
        self.udp.host_info().addr
    }

    /// Returns the host's public key.
    pub fn public_key(&self) -> Key {
        self.udp.host_info().public_key
    }

    // ========================================================================
    // Outbound: TUN -> Peer
    // ========================================================================

    fn outbound_loop(&self) {
        let mut buf = vec![0u8; self.mtu + 40];

        loop {
            if self.closed.load(Ordering::SeqCst) {
                return;
            }

            match self.tun.read(&mut buf) {
                Ok(0) => continue,
                Ok(n) => self.handle_outbound(&buf[..n]),
                Err(e) => {
                    if self.closed.load(Ordering::SeqCst) {
                        return;
                    }
                    eprintln!("host: tun read error: {e}");
                    continue;
                }
            }
        }
    }

    fn handle_outbound(&self, ip_pkt: &[u8]) {
        let info = match parse_ip_packet(ip_pkt) {
            Ok(info) => info,
            Err(_) => return,
        };

        // Look up peer by destination IP
        let dst_ipv4 = match info.dst_ip_v4() {
            Some(ip) => ip,
            None => return,
        };

        let pk = match self.ip_alloc.lookup_by_ip(dst_ipv4) {
            Some(pk) => pk,
            None => return,
        };

        // Map IP protocol number to noise protocol byte and send
        match info.protocol {
            1 => {
                // ICMP
                let _ = self
                    .udp
                    .write_to_protocol(&pk, message::protocol::ICMP, info.payload);
            }
            6 => {
                // TCP
                let _ = self
                    .udp
                    .write_to_protocol(&pk, message::protocol::TCP, info.payload);
            }
            17 => {
                // UDP
                let _ = self
                    .udp
                    .write_to_protocol(&pk, message::protocol::UDP, info.payload);
            }
            _ => {
                // Unrecognized: send complete IP packet with ProtocolIP
                let _ = self
                    .udp
                    .write_to_protocol(&pk, message::protocol::IP, ip_pkt);
            }
        }
    }

    // ========================================================================
    // Inbound: Peer -> TUN
    // ========================================================================

    fn inbound_loop(&self) {
        let mut buf = vec![0u8; 65536];

        loop {
            if self.closed.load(Ordering::SeqCst) {
                return;
            }

            match self.udp.read_packet(&mut buf) {
                Ok((pk, proto, n)) => {
                    if n == 0 {
                        continue;
                    }
                    self.handle_inbound(pk, proto, &buf[..n]);
                }
                Err(e) => {
                    if self.closed.load(Ordering::SeqCst) {
                        return;
                    }
                    eprintln!("host: udp read error: {e:?}");
                    continue;
                }
            }
        }
    }

    fn handle_inbound(&self, pk: Key, proto: u8, payload: &[u8]) {
        match proto {
            p if p == message::protocol::IP => {
                // Complete IP packet - write directly to TUN
                let _ = self.tun.write(payload);
            }
            p if p == message::protocol::ICMP
                || p == message::protocol::TCP
                || p == message::protocol::UDP =>
            {
                // Transport payload without IP header - rebuild and write to TUN
                let src_ip = match self.ip_alloc.lookup_by_pubkey(&pk) {
                    Some(ip) => ip,
                    None => return,
                };

                let ip_pkt = match build_ipv4_packet(src_ip, self.tun_ipv4, proto, payload) {
                    Ok(pkt) => pkt,
                    Err(_) => return,
                };

                let _ = self.tun.write(&ip_pkt);
            }
            _ => {
                // Unknown protocol, ignore
            }
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::SeqCst) {
            self.closed.store(true, Ordering::SeqCst);
            let _ = self.tun.close();
            let _ = self.udp.close();
        }
    }
}

#[cfg(test)]
mod tests;
