//! Unified UDP networking layer for zgrnet.
//!
//! Provides a single `UDP` type that manages multiple peers, handles
//! Noise Protocol handshakes, and supports roaming.

use crate::keypair::{Key, KeyPair, KEY_SIZE};
use crate::handshake::{Config as HandshakeConfig, HandshakeState, Pattern};
use crate::message::{
    self, build_handshake_init, build_handshake_resp, build_transport_message,
    parse_handshake_init, parse_handshake_resp, parse_transport_message,
    MAX_PACKET_SIZE,
};
use crate::session::{generate_index, Session, SessionConfig};

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Peer connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Newly registered peer.
    New,
    /// Performing handshake.
    Connecting,
    /// Session established.
    Established,
    /// Connection failed.
    Failed,
}

impl std::fmt::Display for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerState::New => write!(f, "new"),
            PeerState::Connecting => write!(f, "connecting"),
            PeerState::Established => write!(f, "established"),
            PeerState::Failed => write!(f, "failed"),
        }
    }
}

/// Information about the local host.
#[derive(Debug, Clone)]
pub struct HostInfo {
    pub public_key: Key,
    pub addr: SocketAddr,
    pub peer_count: usize,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_seen: Option<Instant>,
}

/// Information about a peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub public_key: Key,
    pub endpoint: Option<SocketAddr>,
    pub state: PeerState,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_seen: Option<Instant>,
}

/// A peer with its info.
#[derive(Debug)]
pub struct Peer {
    pub info: PeerInfo,
}

/// Errors from UDP operations.
#[derive(Debug)]
pub enum UdpError {
    /// UDP socket is closed.
    Closed,
    /// Peer not found.
    PeerNotFound,
    /// Peer has no endpoint.
    NoEndpoint,
    /// Peer has no established session.
    NoSession,
    /// Handshake failed.
    HandshakeFailed,
    /// Handshake timeout.
    HandshakeTimeout,
    /// IO error.
    Io(io::Error),
    /// Session error.
    Session(String),
}

impl std::fmt::Display for UdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpError::Closed => write!(f, "udp closed"),
            UdpError::PeerNotFound => write!(f, "peer not found"),
            UdpError::NoEndpoint => write!(f, "peer has no endpoint"),
            UdpError::NoSession => write!(f, "peer has no established session"),
            UdpError::HandshakeFailed => write!(f, "handshake failed"),
            UdpError::HandshakeTimeout => write!(f, "handshake timeout"),
            UdpError::Io(e) => write!(f, "io error: {}", e),
            UdpError::Session(e) => write!(f, "session error: {}", e),
        }
    }
}

impl std::error::Error for UdpError {}

impl From<io::Error> for UdpError {
    fn from(e: io::Error) -> Self {
        UdpError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, UdpError>;

/// Internal peer state.
struct PeerStateInternal {
    pk: Key,
    endpoint: Option<SocketAddr>,
    session: Option<Session>,
    state: PeerState,
    rx_bytes: u64,
    tx_bytes: u64,
    last_seen: Option<Instant>,
}

/// Pending handshake tracking.
struct PendingHandshake {
    peer_pk: Key,
    hs_state: HandshakeState,
    local_idx: u32,
    done: std::sync::mpsc::Sender<Result<()>>,
    created_at: Instant,
}

/// Options for creating a UDP instance.
#[derive(Default)]
pub struct UdpOptions {
    /// Address to bind to. Default is "0.0.0.0:0".
    pub bind_addr: Option<String>,
    /// Allow connections from unknown peers.
    pub allow_unknown: bool,
}

impl UdpOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind_addr(mut self, addr: &str) -> Self {
        self.bind_addr = Some(addr.to_string());
        self
    }

    pub fn allow_unknown(mut self, allow: bool) -> Self {
        self.allow_unknown = allow;
        self
    }
}

/// UDP-based network using the Noise Protocol.
///
/// Manages multiple peers, handles handshakes, and supports roaming.
pub struct UDP {
    socket: UdpSocket,
    local_key: KeyPair,
    allow_unknown: bool,

    // Peer management
    peers: RwLock<HashMap<Key, Arc<Mutex<PeerStateInternal>>>>,
    by_index: RwLock<HashMap<u32, Key>>,

    // Pending handshakes (as initiator)
    pending: Mutex<HashMap<u32, PendingHandshake>>,

    // Statistics
    total_rx: AtomicU64,
    total_tx: AtomicU64,
    last_seen: Mutex<Option<Instant>>,

    // State
    closed: AtomicBool,
}

impl UDP {
    /// Creates a new UDP network.
    pub fn new(key: KeyPair, opts: UdpOptions) -> Result<Self> {
        let bind_addr = opts.bind_addr.as_deref().unwrap_or("0.0.0.0:0");
        let socket = UdpSocket::bind(bind_addr)?;

        // Set read timeout for non-blocking behavior in receive loop
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;

        Ok(Self {
            socket,
            local_key: key,
            allow_unknown: opts.allow_unknown,
            peers: RwLock::new(HashMap::new()),
            by_index: RwLock::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            total_rx: AtomicU64::new(0),
            total_tx: AtomicU64::new(0),
            last_seen: Mutex::new(None),
            closed: AtomicBool::new(false),
        })
    }

    /// Sets or updates a peer's endpoint address.
    pub fn set_peer_endpoint(&self, pk: Key, endpoint: SocketAddr) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }

        let mut peers = self.peers.write().unwrap();
        if let Some(peer) = peers.get(&pk) {
            let mut p = peer.lock().unwrap();
            p.endpoint = Some(endpoint);
        } else {
            peers.insert(
                pk,
                Arc::new(Mutex::new(PeerStateInternal {
                    pk,
                    endpoint: Some(endpoint),
                    session: None,
                    state: PeerState::New,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    last_seen: None,
                })),
            );
        }
    }

    /// Removes a peer.
    pub fn remove_peer(&self, pk: &Key) {
        let mut peers = self.peers.write().unwrap();
        if let Some(peer) = peers.remove(pk) {
            let p = peer.lock().unwrap();
            if let Some(ref session) = p.session {
                let mut by_index = self.by_index.write().unwrap();
                by_index.remove(&session.local_index());
            }
        }
    }

    /// Returns information about the local host.
    pub fn host_info(&self) -> HostInfo {
        let peers = self.peers.read().unwrap();
        let last_seen = self.last_seen.lock().unwrap();

        HostInfo {
            public_key: self.local_key.public,
            addr: self.socket.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
            peer_count: peers.len(),
            rx_bytes: self.total_rx.load(Ordering::SeqCst),
            tx_bytes: self.total_tx.load(Ordering::SeqCst),
            last_seen: *last_seen,
        }
    }

    /// Returns information about a specific peer.
    pub fn peer_info(&self, pk: &Key) -> Option<PeerInfo> {
        let peers = self.peers.read().unwrap();
        peers.get(pk).map(|peer| {
            let p = peer.lock().unwrap();
            PeerInfo {
                public_key: p.pk,
                endpoint: p.endpoint,
                state: p.state,
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
                last_seen: p.last_seen,
            }
        })
    }

    /// Returns an iterator over all peers.
    pub fn peers(&self) -> Vec<Peer> {
        let peers = self.peers.read().unwrap();
        peers
            .values()
            .map(|peer| {
                let p = peer.lock().unwrap();
                Peer {
                    info: PeerInfo {
                        public_key: p.pk,
                        endpoint: p.endpoint,
                        state: p.state,
                        rx_bytes: p.rx_bytes,
                        tx_bytes: p.tx_bytes,
                        last_seen: p.last_seen,
                    },
                }
            })
            .collect()
    }

    /// Sends encrypted data to a peer.
    pub fn write_to(&self, pk: &Key, data: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(UdpError::Closed);
        }

        let peers = self.peers.read().unwrap();
        let peer = peers.get(pk).ok_or(UdpError::PeerNotFound)?;
        let mut p = peer.lock().unwrap();

        let endpoint = p.endpoint.ok_or(UdpError::NoEndpoint)?;
        let session = p.session.as_mut().ok_or(UdpError::NoSession)?;

        // Encrypt the data
        let (ciphertext, nonce) = session
            .encrypt(data)
            .map_err(|e| UdpError::Session(e.to_string()))?;

        // Build transport message
        let msg = build_transport_message(session.remote_index(), nonce, &ciphertext);

        // Send
        let n = self.socket.send_to(&msg, endpoint)?;

        // Update stats
        self.total_tx.fetch_add(n as u64, Ordering::SeqCst);
        p.tx_bytes += n as u64;

        Ok(())
    }

    /// Reads the next decrypted message from any peer.
    /// Handles handshakes internally and only returns transport data.
    /// Returns (sender_pk, bytes_read).
    pub fn read_from(&self, buf: &mut [u8]) -> Result<(Key, usize)> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(UdpError::Closed);
        }

        let mut recv_buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err(UdpError::Closed);
            }

            // Read from socket
            let (nr, from) = match self.socket.recv_from(&mut recv_buf) {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => {
                    if self.closed.load(Ordering::SeqCst) {
                        return Err(UdpError::Closed);
                    }
                    return Err(UdpError::Io(e));
                }
            };

            if nr < 1 {
                continue;
            }

            // Update stats
            self.total_rx.fetch_add(nr as u64, Ordering::SeqCst);
            *self.last_seen.lock().unwrap() = Some(Instant::now());

            // Parse message type
            let msg_type = recv_buf[0];

            match msg_type {
                message::message_type::HANDSHAKE_INIT => {
                    self.handle_handshake_init(&recv_buf[..nr], from);
                    continue;
                }
                message::message_type::HANDSHAKE_RESP => {
                    self.handle_handshake_resp(&recv_buf[..nr], from);
                    continue;
                }
                message::message_type::TRANSPORT => {
                    match self.handle_transport(&recv_buf[..nr], from, buf) {
                        Ok((pk, n)) => return Ok((pk, n)),
                        Err(_) => continue,
                    }
                }
                _ => continue,
            }
        }
    }

    /// Initiates a handshake with a peer.
    pub fn connect(&self, pk: &Key) -> Result<()> {
        self.connect_timeout(pk, Duration::from_secs(5))
    }

    /// Initiates a handshake with a peer with timeout.
    pub fn connect_timeout(&self, pk: &Key, timeout: Duration) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(UdpError::Closed);
        }

        let peers = self.peers.read().unwrap();
        let peer = peers.get(pk).ok_or(UdpError::PeerNotFound)?;
        let mut p = peer.lock().unwrap();

        let endpoint = p.endpoint.ok_or(UdpError::NoEndpoint)?;
        p.state = PeerState::Connecting;
        let peer_pk = p.pk;
        drop(p);
        drop(peers);

        // Generate local index
        let local_idx = generate_index();

        // Create handshake state
        let mut hs = HandshakeState::new(HandshakeConfig {
            pattern: Some(Pattern::IK),
            initiator: true,
            local_static: Some(self.local_key.clone()),
            remote_static: Some(peer_pk),
            ..Default::default()
        })
        .map_err(|_| UdpError::HandshakeFailed)?;

        // Write handshake initiation
        let msg1 = hs
            .write_message(&[])
            .map_err(|_| UdpError::HandshakeFailed)?;

        // Build wire message
        let ephemeral = hs.local_ephemeral().ok_or(UdpError::HandshakeFailed)?;
        let wire_msg = build_handshake_init(local_idx, &ephemeral, &msg1[KEY_SIZE..]);

        // Create channel for completion notification
        let (tx, rx) = std::sync::mpsc::channel();

        // Register pending handshake
        {
            let mut pending = self.pending.lock().unwrap();
            pending.insert(
                local_idx,
                PendingHandshake {
                    peer_pk,
                    hs_state: hs,
                    local_idx,
                    done: tx,
                    created_at: Instant::now(),
                },
            );
        }

        // Send handshake initiation
        if let Err(e) = self.socket.send_to(&wire_msg, endpoint) {
            let mut pending = self.pending.lock().unwrap();
            pending.remove(&local_idx);
            return Err(UdpError::Io(e));
        }

        // Wait for response with timeout
        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(_) => {
                let mut pending = self.pending.lock().unwrap();
                pending.remove(&local_idx);

                let peers = self.peers.read().unwrap();
                if let Some(peer) = peers.get(pk) {
                    let mut p = peer.lock().unwrap();
                    p.state = PeerState::Failed;
                }
                Err(UdpError::HandshakeTimeout)
            }
        }
    }

    /// Closes the UDP network.
    pub fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Returns true if the UDP network is closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    // Internal: handle incoming handshake initiation
    fn handle_handshake_init(&self, data: &[u8], from: SocketAddr) {
        let msg = match parse_handshake_init(data) {
            Ok(m) => m,
            Err(_) => return,
        };

        // Create handshake state to process the init
        let mut hs = match HandshakeState::new(HandshakeConfig {
            pattern: Some(Pattern::IK),
            initiator: false,
            local_static: Some(self.local_key.clone()),
            ..Default::default()
        }) {
            Ok(h) => h,
            Err(_) => return,
        };

        // Build Noise message from wire format
        let mut noise_msg = [0u8; KEY_SIZE + 48];
        noise_msg[..KEY_SIZE].copy_from_slice(&msg.ephemeral.0);
        noise_msg[KEY_SIZE..].copy_from_slice(&msg.static_encrypted);

        // Read the handshake message
        if hs.read_message(&noise_msg).is_err() {
            return;
        }

        // Get the remote's public key
        let remote_pk = *hs.remote_static();

        // Check if peer is known or if we allow unknown peers
        {
            let mut peers = self.peers.write().unwrap();
            if !peers.contains_key(&remote_pk) {
                if !self.allow_unknown {
                    return;
                }
                peers.insert(
                    remote_pk,
                    Arc::new(Mutex::new(PeerStateInternal {
                        pk: remote_pk,
                        endpoint: Some(from),
                        session: None,
                        state: PeerState::New,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        last_seen: None,
                    })),
                );
            }
        }

        // Generate local index for response
        let local_idx = generate_index();

        // Write response message
        let resp_payload = match hs.write_message(&[]) {
            Ok(p) => p,
            Err(_) => return,
        };

        // Build wire message
        let ephemeral = match hs.local_ephemeral() {
            Some(e) => e,
            None => return,
        };
        let wire_msg = build_handshake_resp(
            local_idx,
            msg.sender_index,
            &ephemeral,
            &resp_payload[KEY_SIZE..],
        );

        // Send response
        if self.socket.send_to(&wire_msg, from).is_err() {
            return;
        }

        // Complete handshake and create session
        let (send_cs, recv_cs) = match hs.split() {
            Ok((s, r)) => (s, r),
            Err(_) => return,
        };

        let session = Session::new(SessionConfig {
            local_index: local_idx,
            remote_index: msg.sender_index,
            send_key: *send_cs.key(),
            recv_key: *recv_cs.key(),
            remote_pk,
        });

        // Update peer state
        let peers = self.peers.read().unwrap();
        if let Some(peer) = peers.get(&remote_pk) {
            let mut p = peer.lock().unwrap();
            p.endpoint = Some(from);
            p.session = Some(session);
            p.state = PeerState::Established;
            p.last_seen = Some(Instant::now());
        }

        // Register in index map
        let mut by_index = self.by_index.write().unwrap();
        by_index.insert(local_idx, remote_pk);
    }

    // Internal: handle incoming handshake response
    fn handle_handshake_resp(&self, data: &[u8], from: SocketAddr) {
        let msg = match parse_handshake_resp(data) {
            Ok(m) => m,
            Err(_) => return,
        };

        // Find the pending handshake
        let pending = {
            let mut pending_map = self.pending.lock().unwrap();
            match pending_map.remove(&msg.receiver_index) {
                Some(p) => p,
                None => return,
            }
        };

        // Build Noise message from wire format
        let mut noise_msg = [0u8; KEY_SIZE + 16];
        noise_msg[..KEY_SIZE].copy_from_slice(&msg.ephemeral.0);
        noise_msg[KEY_SIZE..].copy_from_slice(&msg.empty_encrypted);

        // Read the handshake response
        let mut hs = pending.hs_state;
        if hs.read_message(&noise_msg).is_err() {
            let peers = self.peers.read().unwrap();
            if let Some(peer) = peers.get(&pending.peer_pk) {
                let mut p = peer.lock().unwrap();
                p.state = PeerState::Failed;
            }
            let _ = pending.done.send(Err(UdpError::HandshakeFailed));
            return;
        }

        // Complete handshake and create session
        let (send_cs, recv_cs) = match hs.split() {
            Ok((s, r)) => (s, r),
            Err(_) => {
                let _ = pending.done.send(Err(UdpError::HandshakeFailed));
                return;
            }
        };

        let session = Session::new(SessionConfig {
            local_index: pending.local_idx,
            remote_index: msg.sender_index,
            send_key: *send_cs.key(),
            recv_key: *recv_cs.key(),
            remote_pk: pending.peer_pk,
        });

        // Update peer state
        let peers = self.peers.read().unwrap();
        if let Some(peer) = peers.get(&pending.peer_pk) {
            let mut p = peer.lock().unwrap();
            p.endpoint = Some(from);
            p.session = Some(session);
            p.state = PeerState::Established;
            p.last_seen = Some(Instant::now());
        }

        // Register in index map
        let mut by_index = self.by_index.write().unwrap();
        by_index.insert(pending.local_idx, pending.peer_pk);

        // Signal completion
        let _ = pending.done.send(Ok(()));
    }

    // Internal: handle incoming transport message
    fn handle_transport(
        &self,
        data: &[u8],
        from: SocketAddr,
        out_buf: &mut [u8],
    ) -> Result<(Key, usize)> {
        let msg = parse_transport_message(data).map_err(|_| UdpError::NoSession)?;

        // Find peer by receiver index
        let peer_pk = {
            let by_index = self.by_index.read().unwrap();
            *by_index.get(&msg.receiver_index).ok_or(UdpError::PeerNotFound)?
        };

        let peers = self.peers.read().unwrap();
        let peer = peers.get(&peer_pk).ok_or(UdpError::PeerNotFound)?;
        let mut p = peer.lock().unwrap();

        let session = p.session.as_mut().ok_or(UdpError::NoSession)?;

        // Decrypt
        let plaintext = session
            .decrypt(msg.ciphertext, msg.counter)
            .map_err(|e| UdpError::Session(e.to_string()))?;

        // Copy to output buffer
        let n = plaintext.len().min(out_buf.len());
        out_buf[..n].copy_from_slice(&plaintext[..n]);

        // Update peer state (roaming + stats)
        if p.endpoint.map(|e| e != from).unwrap_or(true) {
            p.endpoint = Some(from);
        }
        p.rx_bytes += data.len() as u64;
        p.last_seen = Some(Instant::now());

        Ok((peer_pk, n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_udp() {
        let key = KeyPair::generate();
        let udp = UDP::new(key, UdpOptions::new()).unwrap();
        assert!(!udp.is_closed());
        udp.close().unwrap();
        assert!(udp.is_closed());
    }

    #[test]
    fn test_set_peer_endpoint() {
        let key = KeyPair::generate();
        let udp = UDP::new(key, UdpOptions::new()).unwrap();

        let peer_key = KeyPair::generate();
        let endpoint: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        udp.set_peer_endpoint(peer_key.public, endpoint);

        let info = udp.peer_info(&peer_key.public).unwrap();
        assert_eq!(info.endpoint, Some(endpoint));
        assert_eq!(info.state, PeerState::New);
    }

    #[test]
    fn test_remove_peer() {
        let key = KeyPair::generate();
        let udp = UDP::new(key, UdpOptions::new()).unwrap();

        let peer_key = KeyPair::generate();
        let endpoint: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        udp.set_peer_endpoint(peer_key.public, endpoint);
        assert!(udp.peer_info(&peer_key.public).is_some());

        udp.remove_peer(&peer_key.public);
        assert!(udp.peer_info(&peer_key.public).is_none());
    }

    #[test]
    fn test_host_info() {
        let key = KeyPair::generate();
        let udp = UDP::new(key.clone(), UdpOptions::new()).unwrap();

        let info = udp.host_info();
        assert_eq!(info.public_key, key.public);
        assert_eq!(info.peer_count, 0);
    }
}
