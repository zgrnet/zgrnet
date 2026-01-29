//! Connection management for Noise-based communication.
//!
//! This module provides the `Conn` type which manages the handshake process
//! and provides a simple API for sending and receiving encrypted messages.

use std::sync::RwLock;

use crate::handshake::{Config, HandshakeState, Pattern};
use crate::keypair::{Key, KeyPair};
use crate::message::{
    build_handshake_init, build_handshake_resp, build_transport_message, decode_payload,
    encode_payload, parse_handshake_resp, parse_transport_message, HandshakeInit,
    KEY_SIZE, MAX_PACKET_SIZE,
};
use crate::session::{generate_index, Session, SessionConfig};
use crate::transport::{Addr, Transport, TransportError};

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// Newly created connection.
    New,
    /// Handshake in progress.
    Handshaking,
    /// Connection established, ready for data transfer.
    Established,
    /// Connection closed.
    Closed,
}

impl std::fmt::Display for ConnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "new"),
            Self::Handshaking => write!(f, "handshaking"),
            Self::Established => write!(f, "established"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// Connection errors.
#[derive(Debug)]
pub enum ConnError {
    /// Missing local key pair.
    MissingLocalKey,
    /// Missing transport.
    MissingTransport,
    /// Missing remote public key.
    MissingRemotePK,
    /// Missing remote address.
    MissingRemoteAddr,
    /// Invalid connection state.
    InvalidState,
    /// Connection not established.
    NotEstablished,
    /// Invalid receiver index.
    InvalidReceiverIndex,
    /// Handshake not complete.
    HandshakeIncomplete,
    /// Handshake error.
    Handshake(crate::handshake::Error),
    /// Session error.
    Session(crate::session::SessionError),
    /// Message error.
    Message(crate::message::MessageError),
    /// Transport error.
    Transport(TransportError),
}

impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingLocalKey => write!(f, "missing local key pair"),
            Self::MissingTransport => write!(f, "missing transport"),
            Self::MissingRemotePK => write!(f, "missing remote public key"),
            Self::MissingRemoteAddr => write!(f, "missing remote address"),
            Self::InvalidState => write!(f, "invalid connection state"),
            Self::NotEstablished => write!(f, "connection not established"),
            Self::InvalidReceiverIndex => write!(f, "invalid receiver index"),
            Self::HandshakeIncomplete => write!(f, "handshake not complete"),
            Self::Handshake(e) => write!(f, "handshake error: {}", e),
            Self::Session(e) => write!(f, "session error: {}", e),
            Self::Message(e) => write!(f, "message error: {}", e),
            Self::Transport(e) => write!(f, "transport error: {}", e),
        }
    }
}

impl std::error::Error for ConnError {}

impl From<crate::handshake::Error> for ConnError {
    fn from(e: crate::handshake::Error) -> Self {
        Self::Handshake(e)
    }
}

impl From<crate::session::SessionError> for ConnError {
    fn from(e: crate::session::SessionError) -> Self {
        Self::Session(e)
    }
}

impl From<crate::message::MessageError> for ConnError {
    fn from(e: crate::message::MessageError) -> Self {
        Self::Message(e)
    }
}

impl From<TransportError> for ConnError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}

/// Result type for connection operations.
pub type Result<T> = std::result::Result<T, ConnError>;

/// Configuration for creating a connection.
pub struct ConnConfig<T: Transport + 'static> {
    /// Local static key pair.
    pub local_key: KeyPair,
    /// Remote peer's public key (required for initiator).
    pub remote_pk: Option<Key>,
    /// Underlying datagram transport.
    pub transport: T,
    /// Remote peer's address.
    pub remote_addr: Option<Box<dyn Addr>>,
}

/// A connection to a remote peer.
///
/// Manages the handshake process and provides a simple API
/// for sending and receiving encrypted messages.
pub struct Conn<T: Transport + 'static> {
    // Configuration
    local_key: KeyPair,
    remote_pk: RwLock<Key>,
    transport: T,
    remote_addr: RwLock<Option<Box<dyn Addr>>>,

    // State
    state: RwLock<ConnState>,
    session: RwLock<Option<Session>>,
    local_idx: u32,
}

impl<T: Transport + 'static> Conn<T> {
    /// Creates a new connection with the given configuration.
    pub fn new(cfg: ConnConfig<T>) -> Result<Self> {
        let local_idx = generate_index();

        Ok(Self {
            local_key: cfg.local_key,
            remote_pk: RwLock::new(cfg.remote_pk.unwrap_or_default()),
            transport: cfg.transport,
            remote_addr: RwLock::new(cfg.remote_addr),
            state: RwLock::new(ConnState::New),
            session: RwLock::new(None),
            local_idx,
        })
    }

    /// Initiates a handshake with the remote peer.
    /// This is a blocking call that completes the full handshake.
    pub fn open(&self) -> Result<()> {
        // Read required values first (read locks are cheap)
        let remote_pk = *self.remote_pk.read().unwrap();
        if remote_pk.is_zero() {
            return Err(ConnError::MissingRemotePK);
        }
        {
            let remote_addr = self.remote_addr.read().unwrap();
            if remote_addr.is_none() {
                return Err(ConnError::MissingRemoteAddr);
            }
        }

        // Now atomically check and update state (minimizing write lock time)
        {
            let mut state = self.state.write().unwrap();
            if *state != ConnState::New {
                return Err(ConnError::InvalidState);
            }
            *state = ConnState::Handshaking;
        }

        // Create handshake state (IK pattern)
        let hs_result = HandshakeState::new(Config {
            pattern: Some(Pattern::IK),
            initiator: true,
            local_static: Some(self.local_key.clone()),
            remote_static: Some(remote_pk),
            ..Default::default()
        });
        let mut hs = match hs_result {
            Ok(hs) => hs,
            Err(e) => {
                self.fail_handshake();
                return Err(e.into());
            }
        };

        // Generate and send handshake initiation
        let msg1 = match hs.write_message(&[]) {
            Ok(msg) => msg,
            Err(e) => {
                self.fail_handshake();
                return Err(e.into());
            }
        };

        // msg1 format: ephemeral(32) + encrypted_static(48) = 80 bytes
        let wire_msg = build_handshake_init(
            self.local_idx,
            &hs.local_ephemeral().unwrap(),
            &msg1[KEY_SIZE..],
        );

        let remote_addr = self.remote_addr.read().unwrap();
        if let Err(e) = self
            .transport
            .send_to(&wire_msg, remote_addr.as_ref().unwrap().as_ref())
        {
            self.fail_handshake();
            return Err(e.into());
        }

        // Wait for handshake response
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let (n, _) = match self.transport.recv_from(&mut buf) {
            Ok(result) => result,
            Err(e) => {
                self.fail_handshake();
                return Err(e.into());
            }
        };

        // Parse response
        let resp = match parse_handshake_resp(&buf[..n]) {
            Ok(resp) => resp,
            Err(e) => {
                self.fail_handshake();
                return Err(e.into());
            }
        };

        // Verify receiver index matches our sender index
        if resp.receiver_index != self.local_idx {
            self.fail_handshake();
            return Err(ConnError::InvalidReceiverIndex);
        }

        // Reconstruct the noise message and process
        let mut noise_msg = vec![0u8; KEY_SIZE + 16];
        noise_msg[..KEY_SIZE].copy_from_slice(resp.ephemeral.as_bytes());
        noise_msg[KEY_SIZE..].copy_from_slice(&resp.empty_encrypted);

        if let Err(e) = hs.read_message(&noise_msg) {
            self.fail_handshake();
            return Err(e.into());
        }

        // Complete handshake
        self.complete_handshake(&hs, resp.sender_index, None)
    }

    /// Processes an incoming handshake initiation and completes the handshake.
    /// Returns the handshake response to send back.
    pub fn accept(&self, msg: &HandshakeInit) -> Result<Vec<u8>> {
        // Check and update state
        {
            let mut state = self.state.write().unwrap();
            if *state != ConnState::New {
                return Err(ConnError::InvalidState);
            }
            *state = ConnState::Handshaking;
        }

        // Create handshake state (IK pattern - responder)
        let mut hs = match HandshakeState::new(Config {
            pattern: Some(Pattern::IK),
            initiator: false,
            local_static: Some(self.local_key.clone()),
            ..Default::default()
        }) {
            Ok(hs) => hs,
            Err(e) => {
                self.fail_handshake();
                return Err(e.into());
            }
        };

        // Reconstruct the noise message: ephemeral(32) + static_enc(48) = 80 bytes
        let mut noise_msg = vec![0u8; KEY_SIZE + 48];
        noise_msg[..KEY_SIZE].copy_from_slice(msg.ephemeral.as_bytes());
        noise_msg[KEY_SIZE..].copy_from_slice(&msg.static_encrypted);

        if let Err(e) = hs.read_message(&noise_msg) {
            self.fail_handshake();
            return Err(e.into());
        }

        // Get remote public key from handshake
        let remote_pk = *hs.remote_static();

        // Generate response
        let msg2 = match hs.write_message(&[]) {
            Ok(msg) => msg,
            Err(e) => {
                self.fail_handshake();
                return Err(e.into());
            }
        };

        // Store initiator's index as remote index
        let remote_idx = msg.sender_index;

        // Complete handshake (updates remote_pk atomically with state)
        self.complete_handshake(&hs, remote_idx, Some(remote_pk))?;

        // Build wire response message
        Ok(build_handshake_resp(
            self.local_idx,
            remote_idx,
            &hs.local_ephemeral().unwrap(),
            &msg2[KEY_SIZE..],
        ))
    }

    /// Completes the handshake and creates the session.
    /// If remote_pk is provided, it will be set atomically with the state transition.
    fn complete_handshake(&self, hs: &HandshakeState, remote_idx: u32, remote_pk: Option<Key>) -> Result<()> {
        if !hs.is_finished() {
            return Err(ConnError::HandshakeIncomplete);
        }

        // Get transport keys
        let (send_cipher, recv_cipher) = hs.split()?;

        // Update remote_pk if provided (for responder case)
        if let Some(pk) = remote_pk {
            let mut remote_pk_lock = self.remote_pk.write().unwrap();
            *remote_pk_lock = pk;
        }

        // Create session
        let current_remote_pk = *self.remote_pk.read().unwrap();
        let session = Session::new(SessionConfig {
            local_index: self.local_idx,
            remote_index: remote_idx,
            send_key: *send_cipher.key(),
            recv_key: *recv_cipher.key(),
            remote_pk: current_remote_pk,
        });

        // Update state
        {
            let mut session_lock = self.session.write().unwrap();
            *session_lock = Some(session);
        }
        {
            let mut state = self.state.write().unwrap();
            *state = ConnState::Established;
        }

        Ok(())
    }

    /// Handles handshake failure.
    fn fail_handshake(&self) {
        let mut state = self.state.write().unwrap();
        *state = ConnState::New;
    }

    /// Sends an encrypted message to the remote peer.
    pub fn send(&self, protocol: u8, payload: &[u8]) -> Result<()> {
        // Check state and get session info
        let (ciphertext, counter, remote_index) = {
            let state = self.state.read().unwrap();
            if *state != ConnState::Established {
                return Err(ConnError::NotEstablished);
            }

            let session_lock = self.session.read().unwrap();
            let session = session_lock.as_ref().unwrap();

            // Encode and encrypt
            let plaintext = encode_payload(protocol, payload);
            let (ciphertext, counter) = session.encrypt(&plaintext)?;
            (ciphertext, counter, session.remote_index())
        };

        // Get remote address
        let remote_addr = self.remote_addr.read().unwrap();
        let remote_addr = remote_addr.as_ref().ok_or(ConnError::MissingRemoteAddr)?;

        // Build and send message
        let msg = build_transport_message(remote_index, counter, &ciphertext);
        self.transport.send_to(&msg, remote_addr.as_ref())?;

        Ok(())
    }

    /// Receives and decrypts a message from the remote peer.
    /// Returns the protocol byte and decrypted payload.
    ///
    /// For better performance in tight loops, use `recv_with_buffer` with a reusable buffer.
    pub fn recv(&self) -> Result<(u8, Vec<u8>)> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        self.recv_with_buffer(&mut buf)
    }

    /// Receives and decrypts a message using the provided buffer.
    /// This avoids allocating a new buffer on each call.
    /// The buffer should be at least MAX_PACKET_SIZE bytes.
    pub fn recv_with_buffer(&self, buf: &mut [u8]) -> Result<(u8, Vec<u8>)> {
        {
            let state = self.state.read().unwrap();
            if *state != ConnState::Established {
                return Err(ConnError::NotEstablished);
            }
        }

        // Receive packet
        let (n, _) = self.transport.recv_from(buf)?;

        // Parse transport message
        let msg = parse_transport_message(&buf[..n])?;

        // Verify receiver index
        if msg.receiver_index != self.local_idx {
            return Err(ConnError::InvalidReceiverIndex);
        }

        // Decrypt
        let plaintext = {
            let session_lock = self.session.read().unwrap();
            let session = session_lock.as_ref().unwrap();
            session.decrypt(msg.ciphertext, msg.counter)?
        };

        // Decode protocol and payload
        let (protocol, payload) = decode_payload(&plaintext)?;
        Ok((protocol, payload.to_vec()))
    }

    /// Closes the connection.
    pub fn close(&self) -> Result<()> {
        let mut state = self.state.write().unwrap();
        if *state == ConnState::Closed {
            return Ok(());
        }

        *state = ConnState::Closed;
        if let Some(session) = self.session.write().unwrap().as_mut() {
            session.expire();
        }

        Ok(())
    }

    /// Returns the current connection state.
    pub fn state(&self) -> ConnState {
        *self.state.read().unwrap()
    }

    /// Returns the remote peer's public key.
    pub fn remote_public_key(&self) -> Key {
        *self.remote_pk.read().unwrap()
    }

    /// Returns the local session index.
    pub fn local_index(&self) -> u32 {
        self.local_idx
    }

    /// Updates the remote address (for NAT traversal).
    pub fn set_remote_addr(&self, addr: Box<dyn Addr>) {
        let mut remote_addr = self.remote_addr.write().unwrap();
        *remote_addr = Some(addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::parse_handshake_init;
    use crate::transport::MockTransport;
    use std::sync::Arc;

    #[test]
    fn test_conn_state_display() {
        assert_eq!(ConnState::New.to_string(), "new");
        assert_eq!(ConnState::Handshaking.to_string(), "handshaking");
        assert_eq!(ConnState::Established.to_string(), "established");
        assert_eq!(ConnState::Closed.to_string(), "closed");
    }

    #[test]
    fn test_conn_new() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: None,
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        assert_eq!(conn.state(), ConnState::New);
        assert!(conn.local_index() != 0);
    }

    #[test]
    fn test_conn_open_missing_remote_pk() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: None,
            transport: Arc::clone(&transport),
            remote_addr: Some(Box::new(crate::transport::MockAddr::new("peer"))),
        }).unwrap();

        let err = conn.open().unwrap_err();
        assert!(matches!(err, ConnError::MissingRemotePK));
    }

    #[test]
    fn test_conn_open_missing_remote_addr() {
        let key = KeyPair::generate();
        let peer_key = KeyPair::generate();
        let transport = MockTransport::new("test");
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: Some(peer_key.public),
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        let err = conn.open().unwrap_err();
        assert!(matches!(err, ConnError::MissingRemoteAddr));
    }

    #[test]
    fn test_conn_send_not_established() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: None,
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        let err = conn.send(0, b"test").unwrap_err();
        assert!(matches!(err, ConnError::NotEstablished));
    }

    #[test]
    fn test_conn_recv_not_established() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: None,
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        let err = conn.recv().unwrap_err();
        assert!(matches!(err, ConnError::NotEstablished));
    }

    #[test]
    fn test_conn_close() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: None,
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        conn.close().unwrap();
        assert_eq!(conn.state(), ConnState::Closed);

        // Double close should be ok
        conn.close().unwrap();
    }

    #[test]
    fn test_conn_handshake_and_communication() {
        let initiator_key = KeyPair::generate();
        let responder_key = KeyPair::generate();

        let initiator_transport = MockTransport::new("initiator");
        let responder_transport = MockTransport::new("responder");
        MockTransport::connect(&initiator_transport, &responder_transport);

        let initiator = Conn::new(ConnConfig {
            local_key: initiator_key,
            remote_pk: Some(responder_key.public),
            transport: Arc::clone(&initiator_transport),
            remote_addr: Some(Box::new(crate::transport::MockAddr::new("responder"))),
        }).unwrap();

        let responder = Conn::new(ConnConfig {
            local_key: responder_key,
            remote_pk: None,
            transport: Arc::clone(&responder_transport),
            remote_addr: Some(Box::new(crate::transport::MockAddr::new("initiator"))),
        }).unwrap();

        // Spawn responder thread
        let responder_handle = std::thread::spawn(move || {
            // Receive handshake init
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            let (n, _) = responder_transport.recv_from(&mut buf).unwrap();
            let init_msg = parse_handshake_init(&buf[..n]).unwrap();

            // Process and respond
            let resp = responder.accept(&init_msg).unwrap();
            responder_transport.send_to(&resp, &crate::transport::MockAddr::new("initiator")).unwrap();

            responder
        });

        // Give responder time to start
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Initiator opens connection
        initiator.open().unwrap();

        let responder = responder_handle.join().unwrap();

        // Verify both sides are established
        assert_eq!(initiator.state(), ConnState::Established);
        assert_eq!(responder.state(), ConnState::Established);

        // Test communication: initiator -> responder
        initiator.send(crate::message::protocol::CHAT, b"Hello from initiator!").unwrap();
        let (proto, payload) = responder.recv().unwrap();
        assert_eq!(proto, crate::message::protocol::CHAT);
        assert_eq!(payload, b"Hello from initiator!");

        // Test communication: responder -> initiator
        responder.send(crate::message::protocol::RPC, b"Hello from responder!").unwrap();
        let (proto, payload) = initiator.recv().unwrap();
        assert_eq!(proto, crate::message::protocol::RPC);
        assert_eq!(payload, b"Hello from responder!");
    }
}
