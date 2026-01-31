//! Peer manager for managing connections to multiple peers.

use crate::handshake::{Config as HandshakeConfig, HandshakeState, Pattern};
use crate::keypair::{Key, KeyPair, KEY_SIZE};
use crate::message::{
    build_handshake_init, build_handshake_resp, build_transport_message, decode_payload,
    encode_payload, parse_handshake_init, parse_handshake_resp, parse_transport_message,
};
use crate::peer::{Peer, PeerState};
use crate::session::{generate_index, Session, SessionConfig};
use crate::transport::{Addr, Transport, TransportError};
use std::collections::HashMap;
use std::sync::{mpsc, Arc, RwLock};
use std::time::{Duration, Instant};

/// Errors from peer manager operations.
#[derive(Debug)]
pub enum PeerManagerError {
    /// Peer already exists.
    PeerExists,
    /// Peer not found.
    PeerNotFound,
    /// Peer has no endpoint.
    NoEndpoint,
    /// Handshake failed.
    HandshakeFailed,
    /// Handshake timed out.
    HandshakeTimeout,
    /// No pending handshake for index.
    NoPendingHandshake,
    /// Unknown peer (not in allowlist).
    UnknownPeer,
    /// Session not found.
    SessionNotFound,
    /// Connection not established.
    NotEstablished,
    /// Host is closed.
    HostClosed,
    /// Transport error.
    Transport(TransportError),
    /// Session error.
    Session(crate::session::SessionError),
    /// Message error.
    Message(crate::message::MessageError),
    /// Handshake error.
    Handshake(crate::handshake::Error),
}

/// Pending handshake state.
struct PendingHandshake {
    peer: Arc<Peer>,
    hs_state: HandshakeState,
    local_idx: u32,
    done: mpsc::Sender<Result<()>>,
    created_at: Instant,
}

impl std::fmt::Display for PeerManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PeerExists => write!(f, "peer already exists"),
            Self::PeerNotFound => write!(f, "peer not found"),
            Self::NoEndpoint => write!(f, "peer has no endpoint"),
            Self::HandshakeFailed => write!(f, "handshake failed"),
            Self::HandshakeTimeout => write!(f, "handshake timed out"),
            Self::NoPendingHandshake => write!(f, "no pending handshake for index"),
            Self::UnknownPeer => write!(f, "unknown peer"),
            Self::SessionNotFound => write!(f, "session not found"),
            Self::NotEstablished => write!(f, "connection not established"),
            Self::HostClosed => write!(f, "host is closed"),
            Self::Transport(e) => write!(f, "transport error: {}", e),
            Self::Session(e) => write!(f, "session error: {}", e),
            Self::Message(e) => write!(f, "message error: {}", e),
            Self::Handshake(e) => write!(f, "handshake error: {}", e),
        }
    }
}

impl From<crate::handshake::Error> for PeerManagerError {
    fn from(e: crate::handshake::Error) -> Self {
        Self::Handshake(e)
    }
}

impl std::error::Error for PeerManagerError {}

impl From<TransportError> for PeerManagerError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}

impl From<crate::session::SessionError> for PeerManagerError {
    fn from(e: crate::session::SessionError) -> Self {
        Self::Session(e)
    }
}

impl From<crate::message::MessageError> for PeerManagerError {
    fn from(e: crate::message::MessageError) -> Self {
        Self::Message(e)
    }
}

/// Result type for peer manager operations.
pub type Result<T> = std::result::Result<T, PeerManagerError>;

/// Manages all peers and their connections.
pub struct PeerManager<T: Transport + 'static> {
    inner: RwLock<PeerManagerInner>,
    local_key: KeyPair,
    transport: T,
}

struct PeerManagerInner {
    by_pubkey: HashMap<Key, Arc<Peer>>,
    by_index: HashMap<u32, Arc<Peer>>,
    pending: HashMap<u32, PendingHandshake>,
}

impl<T: Transport + 'static> PeerManager<T> {
    /// Creates a new peer manager.
    pub fn new(local_key: KeyPair, transport: T) -> Self {
        Self {
            inner: RwLock::new(PeerManagerInner {
                by_pubkey: HashMap::new(),
                by_index: HashMap::new(),
                pending: HashMap::new(),
            }),
            local_key,
            transport,
        }
    }

    /// Returns a reference to the transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns the local public key.
    pub fn local_public_key(&self) -> Key {
        self.local_key.public
    }

    /// Initiates a connection to a peer with default timeout.
    pub fn dial(&self, pk: &Key) -> Result<()> {
        self.dial_with_timeout(pk, Duration::from_secs(10))
    }

    /// Initiates a connection to a peer with custom timeout.
    pub fn dial_with_timeout(&self, pk: &Key, timeout: Duration) -> Result<()> {
        let peer = self.get_peer(pk).ok_or(PeerManagerError::PeerNotFound)?;

        if peer.is_established() {
            return Ok(());
        }

        let endpoint = peer.endpoint().ok_or(PeerManagerError::NoEndpoint)?;

        // Start async handshake
        let (rx, local_idx) = self.dial_async(peer.clone(), endpoint)?;

        // Wait for completion or timeout
        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Clean up pending handshake using the exact local_idx
                let mut inner = self.inner.write().unwrap();
                inner.pending.remove(&local_idx);
                peer.set_state(PeerState::Failed);
                Err(PeerManagerError::HandshakeTimeout)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                peer.set_state(PeerState::Failed);
                Err(PeerManagerError::HandshakeFailed)
            }
        }
    }

    /// Starts a handshake without blocking.
    /// Returns a channel for completion notification and the local_idx used
    /// to identify this handshake attempt.
    fn dial_async(
        &self,
        peer: Arc<Peer>,
        endpoint: Box<dyn Addr>,
    ) -> Result<(mpsc::Receiver<Result<()>>, u32)> {
        peer.set_state(PeerState::Connecting);

        let local_idx = generate_index();

        // Create handshake state (IK pattern)
        let mut hs = HandshakeState::new(HandshakeConfig {
            pattern: Some(Pattern::IK),
            initiator: true,
            local_static: Some(self.local_key.clone()),
            remote_static: Some(peer.public_key()),
            ..Default::default()
        })?;

        // Generate handshake initiation
        let msg1 = hs.write_message(&[])?;

        // Build wire message
        let ephemeral = hs.local_ephemeral().ok_or(PeerManagerError::HandshakeFailed)?;
        let wire_msg = build_handshake_init(local_idx, &ephemeral, &msg1[KEY_SIZE..]);

        // Create channel for completion notification
        let (tx, rx) = mpsc::channel();

        // Register pending handshake before sending
        {
            let mut inner = self.inner.write().unwrap();
            inner.pending.insert(
                local_idx,
                PendingHandshake {
                    peer: peer.clone(),
                    hs_state: hs,
                    local_idx,
                    done: tx,
                    created_at: Instant::now(),
                },
            );
        }

        // Send handshake initiation
        if let Err(e) = self.transport.send_to(&wire_msg, endpoint.as_ref()) {
            let mut inner = self.inner.write().unwrap();
            inner.pending.remove(&local_idx);
            peer.set_state(PeerState::Failed);
            return Err(e.into());
        }

        Ok((rx, local_idx))
    }

    /// Handles an incoming handshake response.
    pub fn handle_handshake_resp(&self, data: &[u8], from: Box<dyn Addr>) -> Result<()> {
        let resp = parse_handshake_resp(data)?;

        let mut inner = self.inner.write().unwrap();
        let pending = inner
            .pending
            .remove(&resp.receiver_index)
            .ok_or(PeerManagerError::NoPendingHandshake)?;
        drop(inner);

        let peer = pending.peer;
        let mut hs = pending.hs_state;

        // Reconstruct and process noise message
        let mut noise_msg = vec![0u8; KEY_SIZE + 16];
        noise_msg[..KEY_SIZE].copy_from_slice(resp.ephemeral.as_bytes());
        noise_msg[KEY_SIZE..].copy_from_slice(&resp.empty_encrypted);

        if let Err(e) = hs.read_message(&noise_msg) {
            peer.set_state(PeerState::Failed);
            let err: PeerManagerError = e.into();
            let _ = pending.done.send(Err(PeerManagerError::HandshakeFailed));
            return Err(err);
        }

        // Get transport keys
        let (send_cipher, recv_cipher) = match hs.split() {
            Ok(keys) => keys,
            Err(e) => {
                peer.set_state(PeerState::Failed);
                let err: PeerManagerError = e.into();
                let _ = pending.done.send(Err(PeerManagerError::HandshakeFailed));
                return Err(err);
            }
        };

        // Create session
        let session = Session::new(SessionConfig {
            local_index: pending.local_idx,
            remote_index: resp.sender_index,
            send_key: *send_cipher.key(),
            recv_key: *recv_cipher.key(),
            remote_pk: peer.public_key(),
        });

        // Register session
        {
            let mut inner = self.inner.write().unwrap();
            peer.set_session(session);
            inner.by_index.insert(pending.local_idx, peer.clone());
        }

        // Update endpoint (roaming)
        peer.set_endpoint(from);

        // Signal success
        let _ = pending.done.send(Ok(()));
        Ok(())
    }

    /// Handles an incoming handshake initiation (responder side).
    pub fn handle_handshake_init(
        &self,
        data: &[u8],
        from: Box<dyn Addr>,
        allow_unknown: bool,
    ) -> Result<()> {
        use crate::peer::PeerConfig;

        let init = parse_handshake_init(data)?;

        // Create responder handshake state
        let mut hs = HandshakeState::new(HandshakeConfig {
            pattern: Some(Pattern::IK),
            initiator: false,
            local_static: Some(self.local_key.clone()),
            remote_static: None, // Will be learned from message
            ..Default::default()
        })?;

        // Reconstruct noise message (ephemeral + encrypted static + tag)
        let mut noise_msg = vec![0u8; KEY_SIZE + KEY_SIZE + 16 + 16];
        noise_msg[..KEY_SIZE].copy_from_slice(init.ephemeral.as_bytes());
        noise_msg[KEY_SIZE..].copy_from_slice(&init.static_encrypted);

        // Process handshake message
        hs.read_message(&noise_msg)?;

        // Get initiator's static key
        let initiator_pk = *hs.remote_static();
        if initiator_pk.is_zero() {
            return Err(PeerManagerError::HandshakeFailed);
        }

        // Find or create peer
        let peer = if let Some(p) = self.get_peer(&initiator_pk) {
            p
        } else if allow_unknown {
            let p = Arc::new(Peer::new(PeerConfig {
                public_key: initiator_pk,
                endpoint: Some(from.clone_box()),
                mtu: None,
            }));
            self.add_peer(p.clone())?;
            p
        } else {
            return Err(PeerManagerError::UnknownPeer);
        };

        // Generate our index
        let local_idx = generate_index();

        // Generate response message
        let msg2 = hs.write_message(&[])?;

        // Build wire message
        let ephemeral = hs.local_ephemeral().ok_or(PeerManagerError::HandshakeFailed)?;
        let wire_msg = build_handshake_resp(local_idx, init.sender_index, &ephemeral, &msg2[KEY_SIZE..]);

        // Get transport keys
        let (recv_cipher, send_cipher) = hs.split()?; // Note: swapped for responder

        // Create session
        let session = Session::new(SessionConfig {
            local_index: local_idx,
            remote_index: init.sender_index,
            send_key: *send_cipher.key(),
            recv_key: *recv_cipher.key(),
            remote_pk: initiator_pk,
        });

        // Register session
        {
            let mut inner = self.inner.write().unwrap();
            peer.set_session(session);
            peer.set_endpoint(from.clone_box());
            inner.by_index.insert(local_idx, peer.clone());
        }

        // Send response
        self.transport.send_to(&wire_msg, from.as_ref())?;

        Ok(())
    }

    /// Adds a new peer.
    pub fn add_peer(&self, peer: Arc<Peer>) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        let pk = peer.public_key();

        if inner.by_pubkey.contains_key(&pk) {
            return Err(PeerManagerError::PeerExists);
        }

        inner.by_pubkey.insert(pk, peer);
        Ok(())
    }

    /// Removes a peer by public key.
    pub fn remove_peer(&self, pk: &Key) {
        let mut inner = self.inner.write().unwrap();

        if let Some(peer) = inner.by_pubkey.remove(pk) {
            // Remove from index mapping
            if let Some(local_index) = peer.with_session(|s| s.local_index()) {
                inner.by_index.remove(&local_index);
            }
            peer.clear_session();
        }
    }

    /// Gets a peer by public key.
    pub fn get_peer(&self, pk: &Key) -> Option<Arc<Peer>> {
        self.inner.read().unwrap().by_pubkey.get(pk).cloned()
    }

    /// Gets a peer by session index.
    pub fn get_peer_by_index(&self, index: u32) -> Option<Arc<Peer>> {
        self.inner.read().unwrap().by_index.get(&index).cloned()
    }

    /// Lists all peers.
    pub fn list_peers(&self) -> Vec<Arc<Peer>> {
        self.inner.read().unwrap().by_pubkey.values().cloned().collect()
    }

    /// Returns the number of peers.
    pub fn count(&self) -> usize {
        self.inner.read().unwrap().by_pubkey.len()
    }

    /// Sends a message to a peer.
    pub fn send(&self, pk: &Key, protocol: u8, payload: &[u8]) -> Result<()> {
        let peer = self.get_peer(pk).ok_or(PeerManagerError::PeerNotFound)?;

        if !peer.is_established() {
            return Err(PeerManagerError::NotEstablished);
        }

        let endpoint = peer.endpoint().ok_or(PeerManagerError::NoEndpoint)?;

        // Encrypt and send
        let plaintext = encode_payload(protocol, payload);

        let (ciphertext, counter, remote_index) = peer
            .with_session_mut(|session| {
                let (ct, cnt) = session.encrypt(&plaintext)?;
                Ok::<_, crate::session::SessionError>((ct, cnt, session.remote_index()))
            })
            .ok_or(PeerManagerError::NotEstablished)??;

        let msg = build_transport_message(remote_index, counter, &ciphertext);

        peer.add_tx_bytes(msg.len() as u64);
        peer.update_activity();

        self.transport.send_to(&msg, endpoint.as_ref())?;
        Ok(())
    }

    /// Handles an incoming transport message.
    /// Returns the peer, protocol, and payload.
    pub fn handle_transport(
        &self,
        data: &[u8],
        from: Box<dyn Addr>,
    ) -> Result<(Arc<Peer>, u8, Vec<u8>)> {
        let msg = parse_transport_message(data)?;

        let peer = self
            .get_peer_by_index(msg.receiver_index)
            .ok_or(PeerManagerError::SessionNotFound)?;

        // Decrypt
        let plaintext = peer
            .with_session_mut(|session| session.decrypt(msg.ciphertext, msg.counter))
            .ok_or(PeerManagerError::SessionNotFound)??;

        // Decode protocol and payload
        let (protocol, payload) = decode_payload(&plaintext)?;

        // Update stats and roaming
        peer.add_rx_bytes(data.len() as u64);
        peer.update_activity();

        // Roaming: update endpoint if changed
        let current = peer.endpoint();
        if current.is_none() || current.as_ref().map(|e| e.addr_string()) != Some(from.addr_string()) {
            peer.set_endpoint(from);
        }

        Ok((peer, protocol, payload.to_vec()))
    }

    /// Expires stale peers.
    /// Returns the number of peers expired.
    pub fn expire_stale(&self) -> usize {
        let mut inner = self.inner.write().unwrap();

        let expired: Vec<(Key, Option<u32>)> = inner
            .by_pubkey
            .iter()
            .filter(|(_, peer)| peer.is_expired())
            .map(|(pk, peer)| (*pk, peer.with_session(|s| s.local_index())))
            .collect();

        for (pk, local_index) in &expired {
            if let Some(idx) = local_index {
                inner.by_index.remove(idx);
            }
            if let Some(peer) = inner.by_pubkey.get(pk) {
                peer.clear_session();
            }
        }

        expired.len()
    }

    /// Expires pending handshakes that are too old.
    pub fn expire_pending_handshakes(&self, max_age: Duration) -> usize {
        let mut inner = self.inner.write().unwrap();

        let expired: Vec<u32> = inner
            .pending
            .iter()
            .filter(|(_, p)| p.created_at.elapsed() > max_age)
            .map(|(idx, _)| *idx)
            .collect();

        for idx in &expired {
            if let Some(p) = inner.pending.remove(idx) {
                p.peer.set_state(PeerState::Failed);
                let _ = p.done.send(Err(PeerManagerError::HandshakeTimeout));
            }
        }

        expired.len()
    }

    /// Clears all peers and pending handshakes.
    pub fn clear(&self) {
        let mut inner = self.inner.write().unwrap();

        // Cancel all pending handshakes
        for (_, p) in inner.pending.drain() {
            let _ = p.done.send(Err(PeerManagerError::HostClosed));
        }

        for peer in inner.by_pubkey.values() {
            peer.clear_session();
        }

        inner.by_pubkey.clear();
        inner.by_index.clear();
    }

    /// Registers a session for a peer (called after handshake).
    pub fn register_session(&self, pk: &Key, session: Session) {
        let mut inner = self.inner.write().unwrap();

        // Get old index and peer clone first to avoid borrow issues
        let (old_index, peer) = match inner.by_pubkey.get(pk) {
            Some(p) => (p.with_session(|s| s.local_index()), p.clone()),
            None => return,
        };

        // Remove old index mapping
        if let Some(idx) = old_index {
            inner.by_index.remove(&idx);
        }

        let local_index = session.local_index();
        peer.set_session(session);
        inner.by_index.insert(local_index, peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerConfig;
    use crate::transport::MockTransport;

    #[test]
    fn test_new_peer_manager() {
        let kp = KeyPair::generate();
        let transport = MockTransport::new("test");
        let pm = PeerManager::new(kp, transport);

        assert_eq!(pm.count(), 0);
    }

    #[test]
    fn test_add_remove_peer() {
        let kp = KeyPair::generate();
        let peer_kp = KeyPair::generate();
        let transport = MockTransport::new("test");
        let pm = PeerManager::new(kp, transport);

        let peer = Arc::new(Peer::new(PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
            mtu: None,
        }));

        // Add peer
        pm.add_peer(peer.clone()).unwrap();
        assert_eq!(pm.count(), 1);

        // Try duplicate
        let result = pm.add_peer(peer.clone());
        assert!(matches!(result, Err(PeerManagerError::PeerExists)));

        // Get peer
        let got = pm.get_peer(&peer_kp.public);
        assert!(got.is_some());

        // Remove peer
        pm.remove_peer(&peer_kp.public);
        assert_eq!(pm.count(), 0);
        assert!(pm.get_peer(&peer_kp.public).is_none());
    }

    #[test]
    fn test_list_peers() {
        let kp = KeyPair::generate();
        let transport = MockTransport::new("test");
        let pm = PeerManager::new(kp, transport);

        for _ in 0..5 {
            let peer_kp = KeyPair::generate();
            let peer = Arc::new(Peer::new(PeerConfig {
                public_key: peer_kp.public,
                endpoint: None,
                mtu: None,
            }));
            pm.add_peer(peer).unwrap();
        }

        assert_eq!(pm.list_peers().len(), 5);
    }

    #[test]
    fn test_send_not_established() {
        let kp = KeyPair::generate();
        let peer_kp = KeyPair::generate();
        let transport = MockTransport::new("test");
        let pm = PeerManager::new(kp, transport);

        let peer = Arc::new(Peer::new(PeerConfig {
            public_key: peer_kp.public,
            endpoint: None,
            mtu: None,
        }));
        pm.add_peer(peer).unwrap();

        let result = pm.send(&peer_kp.public, 0, b"test");
        assert!(matches!(result, Err(PeerManagerError::NotEstablished)));
    }

    #[test]
    fn test_send_unknown_peer() {
        let kp = KeyPair::generate();
        let unknown_kp = KeyPair::generate();
        let transport = MockTransport::new("test");
        let pm = PeerManager::new(kp, transport);

        let result = pm.send(&unknown_kp.public, 0, b"test");
        assert!(matches!(result, Err(PeerManagerError::PeerNotFound)));
    }

    #[test]
    fn test_clear() {
        let kp = KeyPair::generate();
        let transport = MockTransport::new("test");
        let pm = PeerManager::new(kp, transport);

        for _ in 0..5 {
            let peer_kp = KeyPair::generate();
            let peer = Arc::new(Peer::new(PeerConfig {
                public_key: peer_kp.public,
                endpoint: None,
                mtu: None,
            }));
            pm.add_peer(peer).unwrap();
        }

        pm.clear();
        assert_eq!(pm.count(), 0);
    }
}
