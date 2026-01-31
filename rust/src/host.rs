//! Host is the main entry point for ZGRNet networking.
//!
//! Provides a complete implementation with:
//! - Async handshake support
//! - Background receive loop
//! - Multi-peer management

use crate::keypair::{Key, KeyPair};
use crate::message::{message_type, MAX_PACKET_SIZE};
use crate::peer::{Peer, PeerConfig, PeerInfo, PeerState};
use crate::peer_manager::{PeerManager, PeerManagerError};
use crate::transport::{Addr, Transport, TransportError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Message received from a peer.
#[derive(Debug, Clone)]
pub struct Message {
    pub from: Key,
    pub protocol: u8,
    pub data: Vec<u8>,
}

/// Configuration for creating a Host.
pub struct HostConfig<T: Transport + Send + Sync + 'static> {
    /// The host's identity key pair. If None, a new one is generated.
    pub private_key: Option<KeyPair>,
    /// The transport to use.
    pub transport: T,
    /// Default MTU for new peers.
    pub mtu: Option<u16>,
    /// Whether to allow unknown peers.
    pub allow_unknown_peers: bool,
}

/// Host errors.
#[derive(Debug)]
pub enum HostError {
    /// No transport provided.
    NoTransport,
    /// Host is closed.
    Closed,
    /// Operation timed out.
    Timeout,
    /// Peer manager error.
    PeerManager(PeerManagerError),
    /// Transport error.
    Transport(TransportError),
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTransport => write!(f, "no transport provided"),
            Self::Closed => write!(f, "host is closed"),
            Self::Timeout => write!(f, "operation timed out"),
            Self::PeerManager(e) => write!(f, "peer manager error: {}", e),
            Self::Transport(e) => write!(f, "transport error: {}", e),
        }
    }
}

impl std::error::Error for HostError {}

impl From<PeerManagerError> for HostError {
    fn from(e: PeerManagerError) -> Self {
        Self::PeerManager(e)
    }
}

impl From<TransportError> for HostError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}

/// Result type for host operations.
pub type Result<T> = std::result::Result<T, HostError>;

/// Host is the main entry point for ZGRNet networking.
pub struct Host<T: Transport + Send + Sync + 'static> {
    key_pair: KeyPair,
    peer_manager: Arc<PeerManager<T>>,
    config: HostConfigInner,
    inbox: crossbeam_channel::Receiver<Message>,
    inbox_sender: crossbeam_channel::Sender<Message>,
    closed: Arc<AtomicBool>,
    recv_handle: Option<JoinHandle<()>>,
}

#[derive(Clone)]
struct HostConfigInner {
    mtu: u16,
    allow_unknown_peers: bool,
}

impl<T: Transport + Send + Sync + 'static> Host<T> {
    /// Creates a new Host and starts the background receive loop.
    pub fn new(cfg: HostConfig<T>) -> Result<Self> {
        let key_pair = cfg.private_key.unwrap_or_else(KeyPair::generate);
        let peer_manager = Arc::new(PeerManager::new(key_pair.clone(), cfg.transport));

        let (sender, receiver) = crossbeam_channel::bounded(256);
        let closed = Arc::new(AtomicBool::new(false));

        let config = HostConfigInner {
            mtu: cfg.mtu.unwrap_or(1280),
            allow_unknown_peers: cfg.allow_unknown_peers,
        };

        // Start receive loop
        let recv_handle = {
            let pm = Arc::clone(&peer_manager);
            let inbox = sender.clone();
            let closed_flag = Arc::clone(&closed);
            let cfg = config.clone();

            thread::spawn(move || {
                Self::receive_loop(pm, inbox, closed_flag, cfg);
            })
        };

        Ok(Self {
            key_pair,
            peer_manager,
            config,
            inbox: receiver,
            inbox_sender: sender,
            closed,
            recv_handle: Some(recv_handle),
        })
    }

    /// Background receive loop.
    fn receive_loop(
        pm: Arc<PeerManager<T>>,
        inbox: crossbeam_channel::Sender<Message>,
        closed: Arc<AtomicBool>,
        config: HostConfigInner,
    ) {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        loop {
            if closed.load(Ordering::SeqCst) {
                break;
            }

            // Receive with timeout to allow checking closed flag
            let result = pm.transport().recv_from(&mut buf);

            match result {
                Ok((n, from)) => {
                    if n == 0 {
                        continue;
                    }

                    let msg_type = buf[0];
                    match msg_type {
                        message_type::HANDSHAKE_INIT => {
                            if let Err(e) = pm.handle_handshake_init(&buf[..n], from, config.allow_unknown_peers) {
                                eprintln!("Handshake init error: {}", e);
                            }
                        }
                        message_type::HANDSHAKE_RESP => {
                            if let Err(e) = pm.handle_handshake_resp(&buf[..n], from) {
                                eprintln!("Handshake resp error: {}", e);
                            }
                        }
                        message_type::TRANSPORT => {
                            match pm.handle_transport(&buf[..n], from) {
                                Ok((peer, protocol, data)) => {
                                    let msg = Message {
                                        from: peer.public_key(),
                                        protocol,
                                        data,
                                    };
                                    if let Err(e) = inbox.try_send(msg) {
                                        if e.is_full() {
                                            eprintln!("host: inbox full, dropping message");
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Transport error: {}", e);
                                }
                            }
                        }
                        _ => {
                            // Unknown message type, ignore
                        }
                    }
                }
                Err(TransportError::Closed) => {
                    break;
                }
                Err(TransportError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Timeout, continue loop
                    continue;
                }
                Err(_) => {
                    // Other error, continue
                    continue;
                }
            }
        }
    }

    /// Returns the host's public key.
    pub fn public_key(&self) -> Key {
        self.key_pair.public
    }

    /// Adds a new peer.
    pub fn add_peer(&self, pk: Key, endpoint: Option<Box<dyn Addr>>) -> Result<()> {
        let peer = Arc::new(Peer::new(PeerConfig {
            public_key: pk,
            endpoint,
            mtu: Some(self.config.mtu),
        }));
        self.peer_manager.add_peer(peer)?;
        Ok(())
    }

    /// Removes a peer.
    pub fn remove_peer(&self, pk: &Key) {
        self.peer_manager.remove_peer(pk);
    }

    /// Gets information about a peer.
    pub fn get_peer(&self, pk: &Key) -> Option<PeerInfo> {
        self.peer_manager.get_peer(pk).map(|p| p.info())
    }

    /// Lists all peers.
    pub fn list_peers(&self) -> Vec<PeerInfo> {
        self.peer_manager
            .list_peers()
            .iter()
            .map(|p| p.info())
            .collect()
    }

    /// Connects to a peer (performs handshake).
    pub fn connect(&self, pk: &Key) -> Result<()> {
        self.connect_timeout(pk, Duration::from_secs(10))
    }

    /// Connects to a peer with custom timeout.
    pub fn connect_timeout(&self, pk: &Key, timeout: Duration) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(HostError::Closed);
        }

        self.peer_manager.dial_with_timeout(pk, timeout)?;
        Ok(())
    }

    /// Disconnects from a peer.
    pub fn disconnect(&self, pk: &Key) {
        if let Some(peer) = self.peer_manager.get_peer(pk) {
            peer.clear_session();
            peer.set_state(PeerState::Idle);
        }
    }

    /// Sends a message to a peer.
    pub fn send(&self, pk: &Key, protocol: u8, data: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(HostError::Closed);
        }

        self.peer_manager.send(pk, protocol, data)?;
        Ok(())
    }

    /// Receives a message (blocking).
    pub fn recv(&self) -> Result<Message> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(HostError::Closed);
        }

        self.inbox.recv().map_err(|_| HostError::Closed)
    }

    /// Receives a message with timeout.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Message> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(HostError::Closed);
        }

        self.inbox.recv_timeout(timeout).map_err(|e| match e {
            crossbeam_channel::RecvTimeoutError::Timeout => HostError::Timeout,
            crossbeam_channel::RecvTimeoutError::Disconnected => HostError::Closed,
        })
    }

    /// Closes the host.
    pub fn close(&mut self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        self.peer_manager.clear();
        
        // Close transport to unblock receive loop
        let transport_result = self.peer_manager.transport().close();

        // Wait for receive loop to finish
        if let Some(handle) = self.recv_handle.take() {
            let _ = handle.join();
        }

        transport_result.map_err(HostError::Transport)
    }

    /// Returns true if the host is closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

impl<T: Transport + Send + Sync + 'static> Drop for Host<T> {
    fn drop(&mut self) {
        if !self.is_closed() {
            let _ = self.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;

    #[test]
    fn test_new_host() {
        let kp = KeyPair::generate();
        let transport = MockTransport::new("test");

        let host = Host::new(HostConfig {
            private_key: Some(kp.clone()),
            transport,
            mtu: None,
            allow_unknown_peers: false,
        })
        .unwrap();

        assert_eq!(host.public_key(), kp.public);
    }

    #[test]
    fn test_host_add_remove_peer() {
        let transport = MockTransport::new("test");
        let host = Host::new(HostConfig {
            private_key: None,
            transport,
            mtu: None,
            allow_unknown_peers: false,
        })
        .unwrap();

        let peer_kp = KeyPair::generate();

        host.add_peer(peer_kp.public, None).unwrap();
        assert!(host.get_peer(&peer_kp.public).is_some());

        host.remove_peer(&peer_kp.public);
        assert!(host.get_peer(&peer_kp.public).is_none());
    }

    #[test]
    fn test_host_list_peers() {
        let transport = MockTransport::new("test");
        let host = Host::new(HostConfig {
            private_key: None,
            transport,
            mtu: None,
            allow_unknown_peers: false,
        })
        .unwrap();

        for _ in 0..5 {
            let peer_kp = KeyPair::generate();
            host.add_peer(peer_kp.public, None).unwrap();
        }

        assert_eq!(host.list_peers().len(), 5);
    }

    #[test]
    fn test_host_close() {
        let transport = MockTransport::new("test");
        let mut host = Host::new(HostConfig {
            private_key: None,
            transport,
            mtu: None,
            allow_unknown_peers: false,
        })
        .unwrap();

        assert!(!host.is_closed());
        host.close();
        assert!(host.is_closed());
    }

    #[test]
    fn test_host_recv_after_close() {
        let transport = MockTransport::new("test");
        let mut host = Host::new(HostConfig {
            private_key: None,
            transport,
            mtu: None,
            allow_unknown_peers: false,
        })
        .unwrap();

        host.close();

        let result = host.recv();
        assert!(matches!(result, Err(HostError::Closed)));
    }

    #[test]
    fn test_host_recv_timeout() {
        let transport = MockTransport::new("test");
        let host = Host::new(HostConfig {
            private_key: None,
            transport,
            mtu: None,
            allow_unknown_peers: false,
        })
        .unwrap();

        let result = host.recv_timeout(Duration::from_millis(50));
        assert!(matches!(result, Err(HostError::Timeout)));
    }
}
