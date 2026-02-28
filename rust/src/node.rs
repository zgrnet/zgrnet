//! Embeddable zgrnet network node without TUN.
//!
//! `Node` wraps the low-level UDP transport, Noise Protocol encryption, and KCP
//! stream multiplexing into a simple API suitable for apps and services.
//! Unlike `Host`, Node does not require TUN or root privileges.
//!
//! # Example
//!
//! ```rust,ignore
//! use zgrnet::node::{Node, NodeConfig, PeerConfig};
//! use zgrnet::noise::KeyPair;
//!
//! let key = KeyPair::generate();
//! let node = Node::new(NodeConfig { key, listen_port: 0, allow_unknown: true })?;
//! node.add_peer(PeerConfig { public_key: remote_pk, endpoint: Some("1.2.3.4:51820".into()) })?;
//! let stream = node.dial(&remote_pk, 8080)?;
//! ```

use crate::kcp::SyncStream;
use crate::net::{PeerInfo, PeerState, UdpError, UdpOptions, UDP};
use crate::noise::{Key, KeyPair};
use crate::relay::RouteTable;

use crossbeam_channel::{bounded, Receiver, Sender};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Lifecycle state of a Node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    Stopped = 0,
    Running = 1,
    Suspended = 2,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Stopped => write!(f, "stopped"),
            State::Running => write!(f, "running"),
            State::Suspended => write!(f, "suspended"),
        }
    }
}

/// Errors from Node operations.
#[derive(Debug)]
pub enum NodeError {
    NotRunning,
    AlreadyRunning,
    PeerNotFound,
    NotConnected,
    Stopped,
    Udp(UdpError),
    Io(std::io::Error),
    Other(String),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::NotRunning => write!(f, "node: not running"),
            NodeError::AlreadyRunning => write!(f, "node: already running"),
            NodeError::PeerNotFound => write!(f, "node: peer not found"),
            NodeError::NotConnected => write!(f, "node: peer not connected"),
            NodeError::Stopped => write!(f, "node: stopped"),
            NodeError::Udp(e) => write!(f, "node: udp: {}", e),
            NodeError::Io(e) => write!(f, "node: io: {}", e),
            NodeError::Other(s) => write!(f, "node: {}", s),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<UdpError> for NodeError {
    fn from(e: UdpError) -> Self {
        NodeError::Udp(e)
    }
}

impl From<std::io::Error> for NodeError {
    fn from(e: std::io::Error) -> Self {
        NodeError::Io(e)
    }
}

type Result<T> = std::result::Result<T, NodeError>;

/// Configuration for creating a Node.
pub struct NodeConfig {
    /// Noise Protocol keypair. Required.
    pub key: KeyPair,
    /// UDP port to listen on. 0 for OS-assigned.
    pub listen_port: u16,
    /// Allow connections from peers not added via add_peer.
    pub allow_unknown: bool,
}

/// Configuration for adding a peer.
pub struct PeerConfig {
    /// Peer's Curve25519 public key.
    pub public_key: Key,
    /// Peer's UDP address in "host:port" format. None for responder-only.
    pub endpoint: Option<String>,
}

/// A yamux stream with the remote peer's public key and service ID attached.
pub struct NodeStream {
    pub stream: SyncStream,
    pub remote_pk: Key,
    pub service: u64,
}

impl NodeStream {
    pub fn remote_pubkey(&self) -> Key {
        self.remote_pk
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut s = self.stream.clone();
        io::Read::read(&mut s, buf)
    }

    pub fn write(&self, data: &[u8]) -> io::Result<usize> {
        let mut s = self.stream.clone();
        io::Write::write(&mut s, data)
    }

    pub fn close(&self) {
        self.stream.close();
    }
}

/// An embeddable zgrnet network node.
///
/// Provides Dial (active connect), AcceptStream (passive accept),
/// and raw UDP send/recv — all over Noise-encrypted KCP transport.
/// No TUN device, no root privileges required.
pub struct Node {
    udp: Arc<UDP>,
    state: AtomicU8,

    // Global accept channel aggregates streams from all peers.
    accept_tx: Sender<NodeStream>,
    accept_rx: Receiver<NodeStream>,

    // Per-peer stop signals for accept forwarder threads.
    peer_stops: Mutex<HashMap<Key, Sender<()>>>,

    // Keep track of threads for clean shutdown.
    stop_tx: Sender<()>,
    stop_rx: Receiver<()>,
}

impl Node {
    /// Creates and starts a new Node.
    pub fn new(cfg: NodeConfig) -> Result<Arc<Self>> {
        let bind_addr = format!("127.0.0.1:{}", cfg.listen_port);
        let udp = UDP::new(
            cfg.key,
            UdpOptions::new().bind_addr(&bind_addr).allow_unknown(cfg.allow_unknown),
        )
        .map_err(NodeError::Udp)?;

        let rt = Arc::new(RouteTable::new());
        udp.set_route_table(rt);

        let udp = Arc::new(udp);
        let (accept_tx, accept_rx) = bounded(64);
        let (stop_tx, stop_rx) = bounded(1);

        let node = Arc::new(Self {
            udp,
            state: AtomicU8::new(State::Running as u8),
            accept_tx,
            accept_rx,
            peer_stops: Mutex::new(HashMap::new()),
            stop_tx,
            stop_rx,
        });

        // Start background receive loop.
        let n = Arc::clone(&node);
        thread::spawn(move || n.recv_loop());

        Ok(node)
    }

    /// Shuts down the Node and releases all resources.
    pub fn stop(&self) {
        let prev = self.state.swap(State::Stopped as u8, Ordering::SeqCst);
        if prev == State::Stopped as u8 {
            return; // already stopped
        }

        // Signal stop to all accept forwarder threads.
        let _ = self.stop_tx.try_send(());
        let mut stops = self.peer_stops.lock().unwrap();
        for (_, tx) in stops.drain() {
            let _ = tx.try_send(());
        }

        self.udp.close().ok();
    }

    /// Returns the current lifecycle state.
    pub fn state(&self) -> State {
        match self.state.load(Ordering::SeqCst) {
            1 => State::Running,
            2 => State::Suspended,
            _ => State::Stopped,
        }
    }

    /// Returns this node's public key.
    pub fn public_key(&self) -> Key {
        self.udp.host_info().public_key
    }

    /// Returns the local UDP address.
    pub fn local_addr(&self) -> SocketAddr {
        self.udp.host_info().addr
    }

    /// Registers a peer. If endpoint is provided, the peer can be connected to.
    pub fn add_peer(&self, cfg: PeerConfig) -> Result<()> {
        if self.state() != State::Running {
            return Err(NodeError::NotRunning);
        }

        if let Some(ref ep_str) = cfg.endpoint {
            let ep: SocketAddr = ep_str
                .parse()
                .map_err(|e| NodeError::Other(format!("resolve endpoint: {}", e)))?;
            self.udp.set_peer_endpoint(cfg.public_key, ep);
        } else {
            // Register peer without endpoint.
            self.udp
                .set_peer_endpoint(cfg.public_key, "0.0.0.0:0".parse().unwrap());
        }

        // Start accept forwarder thread for this peer.
        self.start_accept_loop(cfg.public_key);

        Ok(())
    }

    /// Removes a peer.
    pub fn remove_peer(&self, pk: &Key) {
        // Stop the accept forwarder.
        let mut stops = self.peer_stops.lock().unwrap();
        if let Some(tx) = stops.remove(pk) {
            let _ = tx.try_send(());
        }
        drop(stops);

        self.udp.remove_peer(pk);
    }

    /// Returns information about all registered peers.
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.udp.peers().into_iter().map(|p| p.info).collect()
    }

    /// Initiates a handshake with a peer.
    pub fn connect(&self, pk: &Key) -> Result<()> {
        if self.state() != State::Running {
            return Err(NodeError::NotRunning);
        }
        self.udp.connect(pk).map_err(NodeError::from)
    }

    /// Connects to a peer and opens a yamux stream on the given service.
    pub fn dial(&self, pk: &Key, service: u64) -> Result<NodeStream> {
        if self.state() != State::Running {
            return Err(NodeError::NotRunning);
        }

        let info = self.udp.peer_info(pk).ok_or(NodeError::PeerNotFound)?;
        if info.state != PeerState::Established {
            self.udp.connect(pk).map_err(NodeError::from)?;
        }

        let stream = self.udp.open_stream(pk, service).map_err(NodeError::from)?;
        Ok(NodeStream { stream, remote_pk: *pk, service })
    }

    /// Connects to a remote peer through a relay and opens a yamux stream.
    pub fn dial_relay(&self, dst: &Key, relay_pk: &Key, service: u64) -> Result<NodeStream> {
        if self.state() != State::Running {
            return Err(NodeError::NotRunning);
        }

        if let Some(rt) = self.udp.route_table() {
            rt.add_route(dst.0, relay_pk.0);
        }

        self.add_peer(PeerConfig { public_key: *dst, endpoint: None })?;
        self.dial(dst, service)
    }

    /// Returns the node's relay route table.
    pub fn route_table(&self) -> Option<Arc<RouteTable>> {
        self.udp.route_table()
    }

    /// Waits for an incoming yamux stream from any peer.
    pub fn accept_stream(&self) -> Result<NodeStream> {
        self.accept_rx
            .recv()
            .map_err(|_| NodeError::Stopped)
    }

    /// Sends raw data to a peer with the given protocol byte (no stream).
    pub fn write_to(&self, data: &[u8], protocol: u8, pk: &Key) -> Result<()> {
        if self.state() != State::Running {
            return Err(NodeError::NotRunning);
        }
        self.udp
            .write_to_protocol(pk, protocol, data)
            .map_err(NodeError::from)
    }

    /// Reads the next raw packet from any peer.
    /// Returns (bytes_read, protocol, sender_pk).
    pub fn read_from(&self, buf: &mut [u8]) -> Result<(usize, u8, Key)> {
        let (pk, proto, n) = self.udp.read_packet(buf).map_err(NodeError::from)?;
        Ok((n, proto, pk))
    }

    /// Returns the underlying UDP transport. Advanced use only.
    pub fn udp(&self) -> &UDP {
        &self.udp
    }

    // ── Internal ──────────────────────────────────────────────────────

    /// Background receive loop — drives the UDP receive pipeline.
    fn recv_loop(&self) {
        let mut buf = vec![0u8; 65535];
        loop {
            if self.state() == State::Stopped {
                return;
            }
            match self.udp.read_from(&mut buf) {
                Ok(_) => {}
                Err(UdpError::Closed) => return,
                Err(_) => continue,
            }
        }
    }

    /// Starts a thread that forwards accepted streams from one peer
    /// into the global accept channel.
    fn start_accept_loop(&self, pk: Key) {
        let mut stops = self.peer_stops.lock().unwrap();
        if stops.contains_key(&pk) {
            return; // already running
        }
        let (stop_tx, stop_rx) = bounded(1);
        stops.insert(pk, stop_tx);
        drop(stops);

        let udp = Arc::clone(&self.udp);
        let accept_tx = self.accept_tx.clone();
        let global_stop = self.stop_rx.clone();

        thread::spawn(move || {
            // Phase 1: Wait for peer to become established.
            loop {
                if let Some(info) = udp.peer_info(&pk) {
                    if info.state == PeerState::Established {
                        break;
                    }
                }
                // Check stop signals.
                if stop_rx.try_recv().is_ok() || global_stop.try_recv().is_ok() {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }

            // Phase 2: Accept streams.
            loop {
                if stop_rx.try_recv().is_ok() || global_stop.try_recv().is_ok() {
                    return;
                }

                match udp.accept_stream(&pk) {
                    Ok((stream, service)) => {
                        let ns = NodeStream { stream, remote_pk: pk, service };
                        if accept_tx.send(ns).is_err() {
                            return;
                        }
                    }
                    Err(UdpError::Closed) | Err(UdpError::PeerNotFound) => return,
                    Err(_) => {
                        // Transient error (session reset, etc.) — retry after delay.
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        });
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::KeyPair;

    fn gen_key(seed: u8) -> KeyPair {
        let mut private = [0u8; 32];
        private[0] = seed;
        KeyPair::from_private(Key::from(private))
    }

    #[test]
    fn test_new_and_stop() {
        let kp = KeyPair::generate();
        let node = Node::new(NodeConfig {
            key: kp,
            listen_port: 0,
            allow_unknown: false,
        })
        .unwrap();
        assert_eq!(node.state(), State::Running);
        node.stop();
        assert_eq!(node.state(), State::Stopped);
    }

    #[test]
    fn test_double_stop() {
        let kp = KeyPair::generate();
        let node = Node::new(NodeConfig {
            key: kp,
            listen_port: 0,
            allow_unknown: false,
        })
        .unwrap();
        node.stop();
        node.stop(); // should not panic
    }

    #[test]
    fn test_add_peer_and_peers() {
        let kp1 = gen_key(1);
        let kp2 = gen_key(2);
        let node = Node::new(NodeConfig {
            key: kp1,
            listen_port: 0,
            allow_unknown: false,
        })
        .unwrap();

        node.add_peer(PeerConfig {
            public_key: kp2.public,
            endpoint: Some("127.0.0.1:19999".into()),
        })
        .unwrap();

        let peers = node.peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key, kp2.public);

        node.stop();
    }

    #[test]
    fn test_remove_peer() {
        let kp1 = gen_key(1);
        let kp2 = gen_key(2);
        let node = Node::new(NodeConfig {
            key: kp1,
            listen_port: 0,
            allow_unknown: false,
        })
        .unwrap();

        node.add_peer(PeerConfig {
            public_key: kp2.public,
            endpoint: Some("127.0.0.1:19999".into()),
        })
        .unwrap();
        node.remove_peer(&kp2.public);

        assert_eq!(node.peers().len(), 0);
        node.stop();
    }

    #[test]
    fn test_operations_on_stopped_node() {
        let kp = KeyPair::generate();
        let node = Node::new(NodeConfig {
            key: kp,
            listen_port: 0,
            allow_unknown: false,
        })
        .unwrap();
        node.stop();

        assert!(node.add_peer(PeerConfig {
            public_key: Key::default(),
            endpoint: None,
        }).is_err());
        assert!(node.connect(&Key::default()).is_err());
        assert!(node.dial(&Key::default(), 1).is_err());
        assert!(node.write_to(&[], 0, &Key::default()).is_err());
    }
}
