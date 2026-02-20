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

use crate::kcp::Stream as KcpStream;
use crate::net::{PeerInfo, PeerState, UdpError, UdpOptions, UDP};
use crate::noise::{self, Address, Key, KeyPair, ATYP_IPV4};
use crate::relay::RouteTable;

use crossbeam_channel::{bounded, Receiver, Sender};
use std::collections::HashMap;
use std::fmt;
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
    ProtoRegistered,
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
            NodeError::ProtoRegistered => write!(f, "node: proto already registered"),
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

/// A KCP stream with the remote peer's public key attached.
pub struct NodeStream {
    pub stream: Arc<KcpStream>,
    pub remote_pk: Key,
}

/// A raw UDP datagram received from a peer.
pub struct RawPacket {
    pub data: Vec<u8>,
    pub remote_pk: Key,
    pub proto: u8,
}

impl NodeStream {
    /// Returns the remote peer's public key.
    pub fn remote_pubkey(&self) -> Key {
        self.remote_pk
    }

    /// Returns the stream's protocol type.
    pub fn proto(&self) -> u8 {
        self.stream.proto()
    }

    /// Returns the stream's metadata.
    pub fn metadata(&self) -> &[u8] {
        self.stream.metadata()
    }

    /// Reads data from the stream (non-blocking, returns 0 if no data).
    pub fn read(&self, buf: &mut [u8]) -> std::result::Result<usize, crate::kcp::StreamError> {
        self.stream.read_data(buf)
    }

    /// Reads data from the stream (blocking, waits for data).
    pub fn read_blocking(&self, buf: &mut [u8]) -> std::result::Result<usize, crate::kcp::StreamError> {
        self.stream.read_blocking(buf)
    }

    /// Writes data to the stream.
    pub fn write(&self, data: &[u8]) -> std::result::Result<usize, crate::kcp::StreamError> {
        self.stream.write_data(data)
    }

    /// Closes the stream (sends FIN to remote).
    pub fn close(&self) {
        self.stream.shutdown();
    }
}

/// An embeddable zgrnet network node.
///
/// Provides Dial (active connect), Listen/AcceptStream (passive accept),
/// and raw UDP send/recv — all over Noise-encrypted KCP transport.
/// No TUN device, no root privileges required.
pub struct Node {
    udp: Arc<UDP>,
    state: AtomicU8,

    // Global accept channel aggregates streams from all peers.
    accept_tx: Sender<NodeStream>,
    accept_rx: Receiver<NodeStream>,

    // Per-proto stream listeners: proto → sender channel.
    stream_listeners: Arc<Mutex<HashMap<u8, Sender<NodeStream>>>>,

    // Per-proto packet listeners: proto → sender channel.
    packet_listeners: Arc<Mutex<HashMap<u8, Sender<RawPacket>>>>,

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
            stream_listeners: Arc::new(Mutex::new(HashMap::new())),
            packet_listeners: Arc::new(Mutex::new(HashMap::new())),
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

        // Drop all proto listener Senders so accept()/read_from() unblock.
        self.stream_listeners.lock().unwrap().clear();
        self.packet_listeners.lock().unwrap().clear();

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

    /// Connects to a peer and opens a KCP stream.
    ///
    /// If the peer is not yet connected, Dial automatically initiates a handshake.
    /// The stream carries proto=TCP_PROXY with target address 127.0.0.1:port.
    pub fn dial(&self, pk: &Key, port: u16) -> Result<NodeStream> {
        if self.state() != State::Running {
            return Err(NodeError::NotRunning);
        }

        // Ensure peer is connected.
        let info = self.udp.peer_info(pk).ok_or(NodeError::PeerNotFound)?;
        if info.state != PeerState::Established {
            self.udp.connect(pk).map_err(NodeError::from)?;
        }

        // Build target address metadata.
        let addr = Address {
            atyp: ATYP_IPV4,
            host: "127.0.0.1".to_string(),
            port,
        };
        let metadata = addr.encode().map_err(|e| NodeError::Other(format!("{}", e)))?;

        let raw = self
            .udp
            .open_stream(pk, noise::message::protocol::TCP_PROXY, &metadata)
            .map_err(NodeError::from)?;

        Ok(NodeStream {
            stream: raw,
            remote_pk: *pk,
        })
    }

    /// Opens a raw KCP stream with custom proto and metadata.
    pub fn open_stream(&self, pk: &Key, proto: u8, metadata: &[u8]) -> Result<NodeStream> {
        if self.state() != State::Running {
            return Err(NodeError::NotRunning);
        }

        let info = self.udp.peer_info(pk).ok_or(NodeError::PeerNotFound)?;
        if info.state != PeerState::Established {
            self.udp.connect(pk).map_err(NodeError::from)?;
        }

        let raw = self
            .udp
            .open_stream(pk, proto, metadata)
            .map_err(NodeError::from)?;

        Ok(NodeStream {
            stream: raw,
            remote_pk: *pk,
        })
    }

    /// Connects to a remote peer through a relay and opens a KCP stream.
    ///
    /// `relay_pk` is the public key of the relay node. Both this node and
    /// the relay must have established sessions.
    pub fn dial_relay(&self, dst: &Key, relay_pk: &Key, port: u16) -> Result<NodeStream> {
        if self.state() != State::Running {
            return Err(NodeError::NotRunning);
        }

        if let Some(rt) = self.udp.route_table() {
            rt.add_route(dst.0, relay_pk.0);
        }

        self.add_peer(PeerConfig { public_key: *dst, endpoint: None })?;

        self.dial(dst, port)
    }

    /// Returns the node's relay route table.
    pub fn route_table(&self) -> Option<Arc<RouteTable>> {
        self.udp.route_table()
    }

    /// Registers a proto-specific stream listener. All incoming KCP streams
    /// with the given proto are routed here instead of accept_stream().
    /// The listener automatically unregisters when dropped.
    pub fn listen(&self, proto: u8) -> Result<StreamListener> {
        let mut listeners = self.stream_listeners.lock().unwrap();
        if listeners.contains_key(&proto) {
            return Err(NodeError::ProtoRegistered);
        }
        let (tx, rx) = bounded(64);
        listeners.insert(proto, tx);
        Ok(StreamListener {
            proto,
            rx,
            stream_listeners: Arc::clone(&self.stream_listeners),
        })
    }

    /// Registers a proto-specific datagram listener. All incoming raw UDP
    /// packets with the given proto are routed here instead of read_from().
    /// The listener automatically unregisters when dropped.
    pub fn listen_packet(&self, proto: u8) -> Result<PacketListener> {
        let mut listeners = self.packet_listeners.lock().unwrap();
        if listeners.contains_key(&proto) {
            return Err(NodeError::ProtoRegistered);
        }
        let (tx, rx) = bounded(64);
        listeners.insert(proto, tx);
        Ok(PacketListener {
            proto,
            rx,
            packet_listeners: Arc::clone(&self.packet_listeners),
        })
    }

    /// Waits for an incoming KCP stream from any peer.
    /// Streams with a proto that has a registered listen() are NOT delivered here.
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
    /// Also dispatches raw UDP packets to proto-specific PacketListeners.
    fn recv_loop(&self) {
        let mut buf = vec![0u8; 65535];
        loop {
            if self.state() == State::Stopped {
                return;
            }
            match self.udp.read_packet(&mut buf) {
                Ok((pk, proto, n)) => {
                    if n > 0 {
                        let listeners = self.packet_listeners.lock().unwrap();
                        if let Some(tx) = listeners.get(&proto) {
                            let mut data = vec![0u8; n];
                            data.copy_from_slice(&buf[..n]);
                            let _ = tx.try_send(RawPacket {
                                data,
                                remote_pk: pk,
                                proto,
                            });
                        }
                    }
                }
                Err(UdpError::Closed) => return,
                Err(_) => continue,
            }
        }
    }

    /// Starts a thread that forwards accepted streams from one peer
    /// into the global accept channel, routing by proto.
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

        let stream_listeners = Arc::clone(&self.stream_listeners);

        thread::spawn(move || {
            // Phase 1: Wait for peer to become established.
            loop {
                if let Some(info) = udp.peer_info(&pk) {
                    if info.state == PeerState::Established {
                        break;
                    }
                }
                if stop_rx.try_recv().is_ok() || global_stop.try_recv().is_ok() {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }

            // Phase 2: Accept streams — route by proto.
            loop {
                if stop_rx.try_recv().is_ok() || global_stop.try_recv().is_ok() {
                    return;
                }

                match udp.accept_stream(&pk) {
                    Ok(raw) => {
                        let proto = raw.proto();
                        let ns = NodeStream {
                            stream: raw,
                            remote_pk: pk,
                        };

                        // Try proto-specific listener first, fall back to global.
                        let proto_tx = {
                            let listeners = stream_listeners.lock().unwrap();
                            listeners.get(&proto).cloned()
                        };

                        if let Some(tx) = proto_tx {
                            match tx.try_send(ns) {
                                Ok(()) => {}
                                Err(crossbeam_channel::TrySendError::Full(dropped)) => {
                                    dropped.stream.shutdown();
                                }
                                Err(crossbeam_channel::TrySendError::Disconnected(dropped)) => {
                                    dropped.stream.shutdown();
                                }
                            }
                        } else if accept_tx.send(ns).is_err() {
                            return;
                        }
                    }
                    Err(UdpError::Closed) | Err(UdpError::PeerNotFound) => return,
                    Err(_) => {
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

/// Proto-specific KCP stream listener. Created by `Node::listen(proto)`.
/// Automatically unregisters from the Node when dropped.
pub struct StreamListener {
    proto: u8,
    rx: Receiver<NodeStream>,
    stream_listeners: Arc<Mutex<HashMap<u8, Sender<NodeStream>>>>,
}

impl StreamListener {
    /// Waits for the next incoming KCP stream with this listener's proto.
    pub fn accept(&self) -> Result<NodeStream> {
        self.rx.recv().map_err(|_| NodeError::Stopped)
    }

    /// Non-blocking accept.
    pub fn try_accept(&self) -> Option<NodeStream> {
        self.rx.try_recv().ok()
    }

    /// Returns the protocol byte this listener handles.
    pub fn proto(&self) -> u8 {
        self.proto
    }
}

impl Drop for StreamListener {
    fn drop(&mut self) {
        let mut listeners = self.stream_listeners.lock().unwrap();
        listeners.remove(&self.proto);
    }
}

/// Proto-specific raw datagram listener. Created by `Node::listen_packet(proto)`.
/// Automatically unregisters from the Node when dropped.
pub struct PacketListener {
    proto: u8,
    rx: Receiver<RawPacket>,
    packet_listeners: Arc<Mutex<HashMap<u8, Sender<RawPacket>>>>,
}

impl PacketListener {
    /// Waits for the next raw UDP packet with this listener's proto.
    pub fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Key)> {
        let pkt = self.rx.recv().map_err(|_| NodeError::Stopped)?;
        let n = buf.len().min(pkt.data.len());
        buf[..n].copy_from_slice(&pkt.data[..n]);
        Ok((n, pkt.remote_pk))
    }

    /// Returns the protocol byte this listener handles.
    pub fn proto(&self) -> u8 {
        self.proto
    }
}

impl Drop for PacketListener {
    fn drop(&mut self) {
        let mut listeners = self.packet_listeners.lock().unwrap();
        listeners.remove(&self.proto);
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
    fn test_two_nodes_echo() {
        let kp1 = gen_key(1);
        let kp2 = gen_key(2);

        let n1 = Node::new(NodeConfig {
            key: kp1.clone(),
            listen_port: 0,
            allow_unknown: true,
        })
        .unwrap();

        let n2 = Node::new(NodeConfig {
            key: kp2.clone(),
            listen_port: 0,
            allow_unknown: true,
        })
        .unwrap();

        // Add each other as peers.
        let n2_addr = n2.local_addr().to_string();
        let n1_addr = n1.local_addr().to_string();
        n1.add_peer(PeerConfig {
            public_key: kp2.public,
            endpoint: Some(n2_addr),
        })
        .unwrap();
        n2.add_peer(PeerConfig {
            public_key: kp1.public,
            endpoint: Some(n1_addr),
        })
        .unwrap();

        // n1 connects to n2.
        n1.connect(&kp2.public).unwrap();
        thread::sleep(Duration::from_millis(50));

        // n1 dials n2.
        let s1 = n1.dial(&kp2.public, 8080).unwrap();
        assert_eq!(s1.proto(), noise::message::protocol::TCP_PROXY);
        assert_eq!(s1.remote_pubkey(), kp2.public);

        // n2 accepts.
        let s2 = n2.accept_stream().unwrap();
        assert_eq!(s2.proto(), noise::message::protocol::TCP_PROXY);
        assert_eq!(s2.remote_pubkey(), kp1.public);

        // Echo: n1 writes, n2 reads.
        let msg = b"hello from rust node1";
        s1.write(msg).unwrap();

        let mut buf = [0u8; 256];
        let n = read_timeout(&s2, &mut buf, Duration::from_secs(5))
            .expect("read timeout");
        assert_eq!(&buf[..n], msg);

        // Echo back.
        let reply = b"echo: hello from rust node1";
        s2.write(reply).unwrap();

        let n = read_timeout(&s1, &mut buf, Duration::from_secs(5))
            .expect("read reply timeout");
        assert_eq!(&buf[..n], reply);

        s1.close();
        s2.close();
        n1.stop();
        n2.stop();
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
        assert!(node.dial(&Key::default(), 80).is_err());
        assert!(node.write_to(&[], 0, &Key::default()).is_err());
    }

    /// Reads from a NodeStream with a polling timeout.
    #[test]
    fn test_listen_proto_routing() {
        let kp1 = gen_key(0x30);
        let kp2 = gen_key(0x40);

        let n1 = Node::new(NodeConfig {
            key: kp1.clone(),
            listen_port: 0,
            allow_unknown: true,
        })
        .unwrap();

        let n2 = Node::new(NodeConfig {
            key: kp2.clone(),
            listen_port: 0,
            allow_unknown: true,
        })
        .unwrap();

        let n2_addr = n2.local_addr().to_string();
        let n1_addr = n1.local_addr().to_string();
        n1.add_peer(PeerConfig {
            public_key: kp2.public,
            endpoint: Some(n2_addr),
        })
        .unwrap();
        n2.add_peer(PeerConfig {
            public_key: kp1.public,
            endpoint: Some(n1_addr),
        })
        .unwrap();

        n1.connect(&kp2.public).unwrap();
        thread::sleep(Duration::from_millis(50));

        const PROTO_CHAT: u8 = 128;
        const PROTO_FILE: u8 = 200;

        // Register listener for proto=128 on n2.
        let chat_ln = n2.listen(PROTO_CHAT).unwrap();

        // Duplicate registration must fail.
        assert!(matches!(
            n2.listen(PROTO_CHAT),
            Err(NodeError::ProtoRegistered)
        ));

        // n1 opens streams with different protos.
        let chat_stream = n1.open_stream(&kp2.public, PROTO_CHAT, b"chat-meta").unwrap();
        let _file_stream = n1.open_stream(&kp2.public, PROTO_FILE, b"file-meta").unwrap();

        // proto=128 should arrive at chat_ln.
        let accepted_chat = chat_ln.accept().unwrap();
        assert_eq!(accepted_chat.proto(), PROTO_CHAT);
        assert_eq!(accepted_chat.remote_pubkey(), kp1.public);

        // Echo test through the chat listener stream.
        chat_stream.write(b"hello chat").unwrap();
        let mut buf = [0u8; 256];
        let n = read_timeout(&accepted_chat, &mut buf, Duration::from_secs(5))
            .expect("chat read timeout");
        assert_eq!(&buf[..n], b"hello chat");

        // proto=200 should fall through to accept_stream.
        let accepted_file = n2.accept_stream().unwrap();
        assert_eq!(accepted_file.proto(), PROTO_FILE);

        accepted_chat.close();
        accepted_file.close();
        n1.stop();
        n2.stop();
    }

    fn read_timeout(s: &NodeStream, buf: &mut [u8], timeout: Duration) -> Option<usize> {
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                return None;
            }
            match s.read(buf) {
                Ok(0) => thread::sleep(Duration::from_millis(1)),
                Ok(n) => return Some(n),
                Err(_) => return None,
            }
        }
    }
}
