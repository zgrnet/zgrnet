//! Peer management for remote nodes.

use crate::keypair::Key;
use crate::session::Session;
use crate::transport::Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Peer connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Not connected.
    Idle,
    /// Handshake in progress.
    Connecting,
    /// Connection established.
    Established,
    /// Connection attempt failed.
    Failed,
}

impl std::fmt::Display for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Connecting => write!(f, "connecting"),
            Self::Established => write!(f, "established"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Configuration for creating a peer.
pub struct PeerConfig {
    pub public_key: Key,
    pub endpoint: Option<Box<dyn Addr>>,
    pub mtu: Option<u16>,
}

/// Represents a remote node in the network.
pub struct Peer {
    // Identity
    public_key: Key,

    // Connection state (protected by RwLock)
    inner: RwLock<PeerInner>,

    // Timestamps
    created_at: Instant,

    // Statistics (atomic for lock-free updates)
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_pkts: AtomicU64,
    rx_pkts: AtomicU64,
}

struct PeerInner {
    state: PeerState,
    endpoint: Option<Box<dyn Addr>>,
    session: Option<Session>,
    last_handshake: Option<Instant>,
    last_activity: Option<Instant>,
    mtu: u16,
}

impl Peer {
    /// Creates a new peer with the given configuration.
    pub fn new(cfg: PeerConfig) -> Self {
        Self {
            public_key: cfg.public_key,
            inner: RwLock::new(PeerInner {
                state: PeerState::Idle,
                endpoint: cfg.endpoint,
                session: None,
                last_handshake: None,
                last_activity: None,
                mtu: cfg.mtu.unwrap_or(1280), // IPv6 minimum
            }),
            created_at: Instant::now(),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_pkts: AtomicU64::new(0),
            rx_pkts: AtomicU64::new(0),
        }
    }

    /// Returns the peer's public key.
    pub fn public_key(&self) -> Key {
        self.public_key
    }

    /// Returns the current connection state.
    pub fn state(&self) -> PeerState {
        self.inner.read().unwrap().state
    }

    /// Sets the connection state.
    pub fn set_state(&self, state: PeerState) {
        self.inner.write().unwrap().state = state;
    }

    /// Returns the current endpoint.
    pub fn endpoint(&self) -> Option<Box<dyn Addr>> {
        self.inner.read().unwrap().endpoint.clone()
    }

    /// Sets the endpoint (for roaming support).
    pub fn set_endpoint(&self, addr: Box<dyn Addr>) {
        self.inner.write().unwrap().endpoint = Some(addr);
    }

    /// Returns whether the peer has an active session.
    pub fn has_session(&self) -> bool {
        self.inner.read().unwrap().session.is_some()
    }

    /// Sets the session and updates state to established.
    pub fn set_session(&self, session: Session) {
        let mut inner = self.inner.write().unwrap();
        inner.session = Some(session);
        inner.state = PeerState::Established;
        inner.last_handshake = Some(Instant::now());
    }

    /// Clears the session and sets state to idle.
    pub fn clear_session(&self) {
        let mut inner = self.inner.write().unwrap();
        if let Some(ref mut session) = inner.session {
            session.expire();
        }
        inner.session = None;
        inner.state = PeerState::Idle;
    }

    /// Returns the path MTU.
    pub fn mtu(&self) -> u16 {
        self.inner.read().unwrap().mtu
    }

    /// Sets the path MTU.
    pub fn set_mtu(&self, mtu: u16) {
        self.inner.write().unwrap().mtu = mtu;
    }

    /// Returns when the last handshake occurred.
    pub fn last_handshake(&self) -> Option<Instant> {
        self.inner.read().unwrap().last_handshake
    }

    /// Returns when the last activity occurred.
    pub fn last_activity(&self) -> Option<Instant> {
        self.inner.read().unwrap().last_activity
    }

    /// Updates the last activity timestamp.
    pub fn update_activity(&self) {
        self.inner.write().unwrap().last_activity = Some(Instant::now());
    }

    /// Returns when the peer was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Adds to the transmitted bytes counter.
    pub fn add_tx_bytes(&self, n: u64) {
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
        self.tx_pkts.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds to the received bytes counter.
    pub fn add_rx_bytes(&self, n: u64) {
        self.rx_bytes.fetch_add(n, Ordering::Relaxed);
        self.rx_pkts.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the total transmitted bytes.
    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    /// Returns the total received bytes.
    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    /// Returns the total transmitted packets.
    pub fn tx_packets(&self) -> u64 {
        self.tx_pkts.load(Ordering::Relaxed)
    }

    /// Returns the total received packets.
    pub fn rx_packets(&self) -> u64 {
        self.rx_pkts.load(Ordering::Relaxed)
    }

    /// Returns true if the peer has an established connection.
    pub fn is_established(&self) -> bool {
        let inner = self.inner.read().unwrap();
        inner.state == PeerState::Established && inner.session.is_some()
    }

    /// Returns true if the peer's session has expired.
    pub fn is_expired(&self) -> bool {
        let inner = self.inner.read().unwrap();
        match &inner.session {
            Some(session) => session.is_expired(),
            None => false,
        }
    }

    /// Performs an operation with the session.
    /// This avoids cloning the session for simple operations.
    pub fn with_session<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&Session) -> R,
    {
        let inner = self.inner.read().unwrap();
        inner.session.as_ref().map(f)
    }

    /// Performs a mutable operation with the session.
    pub fn with_session_mut<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&mut Session) -> R,
    {
        let mut inner = self.inner.write().unwrap();
        inner.session.as_mut().map(f)
    }

    /// Returns information about the peer.
    pub fn info(&self) -> PeerInfo {
        let inner = self.inner.read().unwrap();
        PeerInfo {
            public_key: self.public_key,
            endpoint: inner.endpoint.as_ref().map(|e| e.addr_string()),
            state: inner.state,
            last_handshake: inner.last_handshake,
            last_activity: inner.last_activity,
            mtu: inner.mtu,
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_packets: self.tx_pkts.load(Ordering::Relaxed),
            rx_packets: self.rx_pkts.load(Ordering::Relaxed),
        }
    }
}

/// Read-only information about a peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub public_key: Key,
    pub endpoint: Option<String>,
    pub state: PeerState,
    pub last_handshake: Option<Instant>,
    pub last_activity: Option<Instant>,
    pub mtu: u16,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
}

impl PeerInfo {
    /// Returns how long since the last handshake.
    pub fn handshake_age(&self) -> Option<Duration> {
        self.last_handshake.map(|t| t.elapsed())
    }

    /// Returns how long since the last activity.
    pub fn idle_time(&self) -> Option<Duration> {
        self.last_activity.map(|t| t.elapsed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::KeyPair;

    #[test]
    fn test_peer_state_display() {
        assert_eq!(PeerState::Idle.to_string(), "idle");
        assert_eq!(PeerState::Connecting.to_string(), "connecting");
        assert_eq!(PeerState::Established.to_string(), "established");
        assert_eq!(PeerState::Failed.to_string(), "failed");
    }

    #[test]
    fn test_new_peer() {
        let kp = KeyPair::generate();
        let peer = Peer::new(PeerConfig {
            public_key: kp.public,
            endpoint: None,
            mtu: None,
        });

        assert_eq!(peer.public_key(), kp.public);
        assert_eq!(peer.state(), PeerState::Idle);
        assert_eq!(peer.mtu(), 1280);
        assert!(!peer.is_established());
    }

    #[test]
    fn test_peer_with_custom_mtu() {
        let kp = KeyPair::generate();
        let peer = Peer::new(PeerConfig {
            public_key: kp.public,
            endpoint: None,
            mtu: Some(1400),
        });

        assert_eq!(peer.mtu(), 1400);
    }

    #[test]
    fn test_peer_state_transitions() {
        let kp = KeyPair::generate();
        let peer = Peer::new(PeerConfig {
            public_key: kp.public,
            endpoint: None,
            mtu: None,
        });

        peer.set_state(PeerState::Connecting);
        assert_eq!(peer.state(), PeerState::Connecting);

        peer.set_state(PeerState::Established);
        assert_eq!(peer.state(), PeerState::Established);

        peer.set_state(PeerState::Failed);
        assert_eq!(peer.state(), PeerState::Failed);
    }

    #[test]
    fn test_peer_statistics() {
        let kp = KeyPair::generate();
        let peer = Peer::new(PeerConfig {
            public_key: kp.public,
            endpoint: None,
            mtu: None,
        });

        assert_eq!(peer.tx_bytes(), 0);
        assert_eq!(peer.rx_bytes(), 0);

        peer.add_tx_bytes(100);
        peer.add_tx_bytes(50);
        peer.add_rx_bytes(200);

        assert_eq!(peer.tx_bytes(), 150);
        assert_eq!(peer.rx_bytes(), 200);
        assert_eq!(peer.tx_packets(), 2);
        assert_eq!(peer.rx_packets(), 1);
    }

    #[test]
    fn test_peer_activity() {
        let kp = KeyPair::generate();
        let peer = Peer::new(PeerConfig {
            public_key: kp.public,
            endpoint: None,
            mtu: None,
        });

        assert!(peer.last_activity().is_none());

        peer.update_activity();
        assert!(peer.last_activity().is_some());
    }

    #[test]
    fn test_peer_info() {
        let kp = KeyPair::generate();
        let peer = Peer::new(PeerConfig {
            public_key: kp.public,
            endpoint: None,
            mtu: Some(1400),
        });

        peer.add_tx_bytes(100);
        peer.add_rx_bytes(200);
        peer.set_state(PeerState::Established);

        let info = peer.info();
        assert_eq!(info.public_key, kp.public);
        assert_eq!(info.state, PeerState::Established);
        assert_eq!(info.mtu, 1400);
        assert_eq!(info.tx_bytes, 100);
        assert_eq!(info.rx_bytes, 200);
    }
}
