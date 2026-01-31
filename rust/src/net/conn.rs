//! Connection management for Noise-based communication.
//!
//! This module provides the `Conn` type which manages the handshake process
//! and provides a simple API for sending and receiving encrypted messages.

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Mutex, RwLock};
use std::time::Instant;

use crate::noise::{
    // Handshake
    Config, HandshakeState, Pattern,
    // Keypair
    Key, KeyPair, KEY_SIZE,
    // Message
    build_handshake_init, build_handshake_resp, build_transport_message, encode_payload,
    parse_handshake_resp, parse_transport_message, HandshakeInit, MAX_PACKET_SIZE,
    // Session
    generate_index, Session, SessionConfig, SessionError,
    // Transport
    Addr, Transport, TransportError,
    // Error
    Error as HandshakeError,
};

use super::consts::{
    KEEPALIVE_TIMEOUT, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME, REKEY_ATTEMPT_TIME,
    REKEY_TIMEOUT, REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME,
};

/// An inbound packet from the listener.
/// Contains an owned copy of the transport message data.
pub struct InboundPacket {
    /// Receiver's session index.
    pub receiver_index: u32,
    /// Counter/nonce.
    pub counter: u64,
    /// Ciphertext (owned).
    pub ciphertext: Vec<u8>,
    /// Source address.
    pub addr: Box<dyn Addr>,
}

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
    /// Connection timed out (no data received for too long).
    ConnTimeout,
    /// Handshake attempt exceeded maximum duration.
    HandshakeTimeout,
    /// Session expired (too old or too many messages).
    SessionExpired,
    /// Handshake error.
    Handshake(HandshakeError),
    /// Session error.
    Session(SessionError),
    /// Message error.
    Message(crate::noise::MessageError),
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
            Self::ConnTimeout => write!(f, "connection timed out"),
            Self::HandshakeTimeout => write!(f, "handshake timeout"),
            Self::SessionExpired => write!(f, "session expired"),
            Self::Handshake(e) => write!(f, "handshake error: {}", e),
            Self::Session(e) => write!(f, "session error: {}", e),
            Self::Message(e) => write!(f, "message error: {}", e),
            Self::Transport(e) => write!(f, "transport error: {}", e),
        }
    }
}

impl std::error::Error for ConnError {}

impl From<HandshakeError> for ConnError {
    fn from(e: HandshakeError) -> Self {
        Self::Handshake(e)
    }
}

impl From<SessionError> for ConnError {
    fn from(e: SessionError) -> Self {
        Self::Session(e)
    }
}

impl From<crate::noise::MessageError> for ConnError {
    fn from(e: crate::noise::MessageError) -> Self {
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
///
/// The connection follows WireGuard's timer model:
/// - `tick()` is called periodically to handle time-based actions
/// - `send()` queues data if no session and triggers handshake
/// - `recv()` processes incoming messages and updates state
pub struct Conn<T: Transport + 'static> {
    // Configuration
    local_key: KeyPair,
    remote_pk: RwLock<Key>,
    transport: T,
    remote_addr: RwLock<Option<Box<dyn Addr>>>,

    // State
    state: RwLock<ConnState>,
    local_idx: u32,

    // Session management (WireGuard-style rotation)
    // current: active session for sending
    // previous: previous session (for receiving delayed packets)
    current: RwLock<Option<Session>>,
    previous: RwLock<Option<Session>>,

    // Timestamps
    created_at: Instant,
    session_created: RwLock<Option<Instant>>,
    last_sent: RwLock<Option<Instant>>,
    last_received: RwLock<Option<Instant>>,
    handshake_attempt_start: RwLock<Option<Instant>>,
    last_handshake_sent: RwLock<Option<Instant>>,

    // Role
    is_initiator: RwLock<bool>,

    // Rekey state
    rekey_triggered: RwLock<bool>,

    // Inbound channel for listener-managed connections
    // When set, recv() reads from this channel instead of the transport
    inbound_tx: Mutex<Option<Sender<InboundPacket>>>,
    inbound_rx: Mutex<Option<Receiver<InboundPacket>>>,
}

impl<T: Transport + 'static> Conn<T> {
    /// Creates a new connection with the given configuration.
    pub fn new(cfg: ConnConfig<T>) -> Result<Self> {
        let local_idx = generate_index();
        let now = Instant::now();

        Ok(Self {
            local_key: cfg.local_key,
            remote_pk: RwLock::new(cfg.remote_pk.unwrap_or_default()),
            transport: cfg.transport,
            remote_addr: RwLock::new(cfg.remote_addr),
            state: RwLock::new(ConnState::New),
            local_idx,
            current: RwLock::new(None),
            previous: RwLock::new(None),
            created_at: now,
            session_created: RwLock::new(None),
            last_sent: RwLock::new(None),
            last_received: RwLock::new(None),
            handshake_attempt_start: RwLock::new(None),
            last_handshake_sent: RwLock::new(None),
            is_initiator: RwLock::new(false),
            rekey_triggered: RwLock::new(false),
            inbound_tx: Mutex::new(None),
            inbound_rx: Mutex::new(None),
        })
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
            let mut session_lock = self.current.write().unwrap();
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

            let session_lock = self.current.read().unwrap();
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

    /// Receives and decrypts a message using the provided buffer for network I/O.
    /// This avoids allocating a new buffer for receiving on each call.
    /// The buffer should be at least MAX_PACKET_SIZE bytes.
    pub fn recv_with_buffer(&self, buf: &mut [u8]) -> Result<(u8, Vec<u8>)> {
        let (protocol, plaintext) = self.recv_internal(buf)?;
        // Skip protocol byte and return owned payload
        Ok((protocol, plaintext[1..].to_vec()))
    }

    /// Receives and decrypts a message into the provided output buffer.
    /// This is the most efficient receive method, avoiding all intermediate allocations.
    /// 
    /// # Arguments
    /// * `recv_buf` - Buffer for receiving network data (should be at least MAX_PACKET_SIZE)
    /// * `out_buf` - Buffer to write decrypted payload into
    /// 
    /// # Returns
    /// * `(protocol, bytes_written)` - The protocol byte and number of bytes written to out_buf
    pub fn recv_into(&self, recv_buf: &mut [u8], out_buf: &mut [u8]) -> Result<(u8, usize)> {
        let (protocol, plaintext) = self.recv_internal(recv_buf)?;
        let payload = &plaintext[1..]; // Skip protocol byte
        let n = std::cmp::min(out_buf.len(), payload.len());
        out_buf[..n].copy_from_slice(&payload[..n]);
        Ok((protocol, n))
    }

    /// Internal receive implementation that returns the decrypted plaintext.
    fn recv_internal(&self, buf: &mut [u8]) -> Result<(u8, Vec<u8>)> {
        {
            let state = self.state.read().unwrap();
            if *state != ConnState::Established {
                return Err(ConnError::NotEstablished);
            }
        }

        // Check if we have an inbound channel (listener-managed connection)
        let has_inbound = self.inbound_rx.lock().unwrap().is_some();

        if has_inbound {
            // Listener-managed connection: read pre-parsed message from inbound channel
            let rx_guard = self.inbound_rx.lock().unwrap();
            let rx = rx_guard.as_ref().unwrap();
            
            // This will block until a packet arrives or the channel is closed
            let pkt = rx.recv().map_err(|_| ConnError::InvalidState)?;
            drop(rx_guard); // Release lock before decryption
            
            // Update remote address for NAT traversal
            self.set_remote_addr(pkt.addr);
            
            // Verify receiver index
            if pkt.receiver_index != self.local_idx {
                return Err(ConnError::InvalidReceiverIndex);
            }

            // Decrypt
            let plaintext = {
                let session_lock = self.current.read().unwrap();
                let session = session_lock.as_ref().unwrap();
                session.decrypt(&pkt.ciphertext, pkt.counter)?
            };

            let protocol = plaintext.first().copied().unwrap_or(0);
            return Ok((protocol, plaintext));
        }

        // Direct connection: receive packet from transport
        let (n, _) = self.transport.recv_from(buf)?;

        // Parse transport message
        let msg = parse_transport_message(&buf[..n])?;

        // Verify receiver index
        if msg.receiver_index != self.local_idx {
            return Err(ConnError::InvalidReceiverIndex);
        }

        // Decrypt
        let plaintext = {
            let session_lock = self.current.read().unwrap();
            let session = session_lock.as_ref().unwrap();
            session.decrypt(msg.ciphertext, msg.counter)?
        };

        // Return protocol and full plaintext (including protocol byte)
        let protocol = plaintext.first().copied().unwrap_or(0);
        Ok((protocol, plaintext))
    }

    /// Performs periodic maintenance on the connection.
    /// This method should be called periodically by the connection manager.
    ///
    /// Tick directly executes time-based actions:
    /// - Sends keepalive if we haven't sent anything recently but have received data
    /// - Triggers rekey if session is too old (initiator only)
    ///
    /// Returns Ok(()) on success. Returns an error if:
    /// - `ConnTimeout`: connection timed out (no data received for RejectAfterTime)
    /// - `HandshakeTimeout`: handshake attempt exceeded RekeyAttemptTime (90s)
    /// - `SessionExpired`: session expired (too many messages)
    pub fn tick(&self) -> Result<()> {
        let now = Instant::now();
        let state = *self.state.read().unwrap();

        match state {
            ConnState::New => {
                // Nothing to do for new connections
                Ok(())
            }
            ConnState::Handshaking => {
                // Check if handshake attempt has exceeded RekeyAttemptTime (90s)
                if let Some(start) = *self.handshake_attempt_start.read().unwrap() {
                    if now.duration_since(start) > REKEY_ATTEMPT_TIME {
                        return Err(ConnError::HandshakeTimeout);
                    }
                }
                Ok(())
            }
            ConnState::Established => {
                // Check if connection has timed out (no messages received)
                if let Some(last_recv) = *self.last_received.read().unwrap() {
                    if now.duration_since(last_recv) > REJECT_AFTER_TIME {
                        return Err(ConnError::ConnTimeout);
                    }
                }

                // Check message-based rejection (nonce exhaustion)
                if let Some(ref session) = *self.current.read().unwrap() {
                    let send_nonce = session.send_nonce();
                    let recv_nonce = session.recv_max_nonce();
                    if send_nonce > REJECT_AFTER_MESSAGES || recv_nonce > REJECT_AFTER_MESSAGES {
                        return Err(ConnError::SessionExpired);
                    }
                }

                // Check if rekey is needed (session too old or too many messages, initiator only)
                let is_initiator = *self.is_initiator.read().unwrap();
                let rekey_triggered = *self.rekey_triggered.read().unwrap();

                if is_initiator && !rekey_triggered {
                    let mut needs_rekey = false;

                    // Time-based rekey trigger
                    if let Some(session_time) = *self.session_created.read().unwrap() {
                        if now.duration_since(session_time) > REKEY_AFTER_TIME {
                            needs_rekey = true;
                        }
                    }

                    // Message-based rekey trigger
                    if let Some(ref session) = *self.current.read().unwrap() {
                        let send_nonce = session.send_nonce();
                        let recv_nonce = session.recv_max_nonce();
                        if send_nonce > REKEY_AFTER_MESSAGES || recv_nonce > REKEY_AFTER_MESSAGES {
                            needs_rekey = true;
                        }
                    }

                    if needs_rekey {
                        *self.rekey_triggered.write().unwrap() = true;
                        // Note: Actual rekey initiation would happen here
                        // For now, we just mark that rekey is needed
                    }
                }

                // Passive keepalive: send empty message if we haven't sent recently
                // but have received data recently (peer is active)
                if let (Some(last_sent_time), Some(last_recv_time)) = (
                    *self.last_sent.read().unwrap(),
                    *self.last_received.read().unwrap(),
                ) {
                    let sent_delta = now.duration_since(last_sent_time);
                    let recv_delta = now.duration_since(last_recv_time);
                    if sent_delta > KEEPALIVE_TIMEOUT && recv_delta < KEEPALIVE_TIMEOUT {
                        // Send keepalive (empty data message)
                        let _ = self.send(0, &[]);
                    }
                }

                Ok(())
            }
            ConnState::Closed => Err(ConnError::InvalidState),
        }
    }

    /// Closes the connection.
    pub fn close(&self) -> Result<()> {
        let mut state = self.state.write().unwrap();
        if *state == ConnState::Closed {
            return Ok(());
        }

        *state = ConnState::Closed;
        if let Some(session) = self.current.write().unwrap().as_mut() {
            session.expire();
        }

        Ok(())
    }

    /// Returns a reference to the transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns the current connection state.
    pub fn state(&self) -> ConnState {
        *self.state.read().unwrap()
    }

    /// Sets the connection state.
    pub(crate) fn set_state(&self, new_state: ConnState) {
        let mut state = self.state.write().unwrap();
        *state = new_state;
    }

    /// Sets the current session.
    pub(crate) fn set_session(&self, session: Session) {
        let mut current = self.current.write().unwrap();
        *current = Some(session);
        let mut session_created = self.session_created.write().unwrap();
        *session_created = Some(Instant::now());
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

    /// Sets up the inbound channel for listener-managed connections.
    /// Returns the sender side for the listener to use.
    /// This should only be called by Listener before the connection is returned.
    pub(crate) fn setup_inbound(&self) -> Sender<InboundPacket> {
        let (tx, rx) = channel();
        *self.inbound_tx.lock().unwrap() = Some(tx.clone());
        *self.inbound_rx.lock().unwrap() = Some(rx);
        tx
    }

    /// Delivers a parsed transport message to the connection's inbound channel.
    /// Returns false if the channel is full or the connection is closed.
    pub(crate) fn deliver_packet(&self, pkt: InboundPacket) -> bool {
        let state = *self.state.read().unwrap();
        if state == ConnState::Closed {
            return false;
        }

        if let Some(ref tx) = *self.inbound_tx.lock().unwrap() {
            tx.send(pkt).is_ok()
        } else {
            false
        }
    }

    /// Returns whether this connection has an inbound channel (listener-managed).
    pub fn has_inbound(&self) -> bool {
        self.inbound_rx.lock().unwrap().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::{parse_handshake_init, MockTransport, MockAddr};
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
        use crate::net::dial::{dial, DialOptions};

        let initiator_key = KeyPair::generate();
        let responder_key = KeyPair::generate();

        let initiator_transport = MockTransport::new("initiator");
        let responder_transport = MockTransport::new("responder");
        MockTransport::connect(&initiator_transport, &responder_transport);

        let responder = Conn::new(ConnConfig {
            local_key: responder_key.clone(),
            remote_pk: None,
            transport: Arc::clone(&responder_transport),
            remote_addr: Some(Box::new(MockAddr::new("initiator"))),
        }).unwrap();

        // Spawn responder thread
        let responder_handle = std::thread::spawn(move || {
            // Receive handshake init
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            let (n, _) = responder_transport.recv_from(&mut buf).unwrap();
            let init_msg = parse_handshake_init(&buf[..n]).unwrap();

            // Process and respond
            let resp = responder.accept(&init_msg).unwrap();
            responder_transport.send_to(&resp, &MockAddr::new("initiator")).unwrap();

            responder
        });

        // Give responder time to start
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Initiator dials connection
        let initiator = dial(DialOptions {
            local_key: initiator_key,
            remote_pk: responder_key.public,
            transport: Arc::clone(&initiator_transport),
            remote_addr: Box::new(MockAddr::new("responder")),
            deadline: None,
        }).unwrap();

        let responder = responder_handle.join().unwrap();

        // Verify both sides are established
        assert_eq!(initiator.state(), ConnState::Established);
        assert_eq!(responder.state(), ConnState::Established);

        // Test communication: initiator -> responder
        initiator.send(crate::noise::protocol::CHAT, b"Hello from initiator!").unwrap();
        let (proto, payload) = responder.recv().unwrap();
        assert_eq!(proto, crate::noise::protocol::CHAT);
        assert_eq!(payload, b"Hello from initiator!");

        // Test communication: responder -> initiator
        responder.send(crate::noise::protocol::RPC, b"Hello from responder!").unwrap();
        let (proto, payload) = initiator.recv().unwrap();
        assert_eq!(proto, crate::noise::protocol::RPC);
        assert_eq!(payload, b"Hello from responder!");
    }
}
