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
    parse_transport_message, HandshakeInit, MAX_PACKET_SIZE,
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
    /// Connection closed.
    ConnClosed,
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
    /// Handshake failed.
    HandshakeFailed,
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
            Self::ConnClosed => write!(f, "connection closed"),
            Self::InvalidReceiverIndex => write!(f, "invalid receiver index"),
            Self::HandshakeIncomplete => write!(f, "handshake not complete"),
            Self::ConnTimeout => write!(f, "connection timed out"),
            Self::HandshakeTimeout => write!(f, "handshake timeout"),
            Self::SessionExpired => write!(f, "session expired"),
            Self::HandshakeFailed => write!(f, "handshake failed"),
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
    #[allow(dead_code)] // Reserved for session rotation (rekey)
    previous: RwLock<Option<Session>>,

    // Handshake state (for pending rekey)
    hs_state: RwLock<Option<HandshakeState>>,
    handshake_started: RwLock<Option<Instant>>,

    // Timestamps
    session_created: RwLock<Option<Instant>>,
    last_sent: RwLock<Option<Instant>>,
    last_received: RwLock<Option<Instant>>,
    handshake_attempt_start: RwLock<Option<Instant>>,
    last_handshake_sent: RwLock<Option<Instant>>,

    // Role
    is_initiator: RwLock<bool>,

    // Rekey state
    rekey_triggered: RwLock<bool>,

    // Pending packets waiting for session establishment
    pending_packets: Mutex<Vec<Vec<u8>>>,

    // Inbound channel for listener-managed connections
    // When set, recv() reads from this channel instead of the transport
    inbound_tx: Mutex<Option<Sender<InboundPacket>>>,
    inbound_rx: Mutex<Option<Receiver<InboundPacket>>>,
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
            local_idx,
            current: RwLock::new(None),
            previous: RwLock::new(None),
            hs_state: RwLock::new(None),
            handshake_started: RwLock::new(None),
            session_created: RwLock::new(None),
            last_sent: RwLock::new(None),
            last_received: RwLock::new(None),
            handshake_attempt_start: RwLock::new(None),
            last_handshake_sent: RwLock::new(None),
            is_initiator: RwLock::new(false),
            rekey_triggered: RwLock::new(false),
            pending_packets: Mutex::new(Vec::new()),
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
        {
            *self.session_created.write().unwrap() = Some(Instant::now());
            *self.last_sent.write().unwrap() = Some(Instant::now());
            *self.last_received.write().unwrap() = Some(Instant::now());
            *self.rekey_triggered.write().unwrap() = false;
        }

        // Flush any pending packets (outside locks)
        self.flush_pending_packets();

        Ok(())
    }

    /// Flushes pending packets after session establishment.
    fn flush_pending_packets(&self) {
        let packets: Vec<Vec<u8>> = {
            let mut pending = self.pending_packets.lock().unwrap();
            std::mem::take(&mut *pending)
        };

        for pkt in packets {
            // Ignore errors - best effort delivery
            let _ = self.send_payload(pkt, false);
        }
    }

    /// Handles handshake failure.
    fn fail_handshake(&self) {
        let mut state = self.state.write().unwrap();
        *state = ConnState::New;
    }

    /// Sends an encrypted message to the remote peer.
    ///
    /// If the connection is not established, the packet is queued and
    /// will be sent once the handshake completes. Returns `NotEstablished`
    /// to indicate the packet was queued (not an error in this context).
    pub fn send(&self, protocol: u8, payload: &[u8]) -> Result<()> {
        // Perform health check first (like Go's tick(true))
        // Ignore NotEstablished/Closed errors - we'll queue the packet
        if let Err(e) = self.tick() {
            match e {
                ConnError::NotEstablished | ConnError::ConnClosed => {}
                _ => return Err(e), // Other errors (timeout, expired) are fatal
            }
        }

        let plaintext = encode_payload(protocol, payload);
        self.send_payload(plaintext, false)
    }

    /// Internal send implementation shared by send() and send_keepalive().
    fn send_payload(&self, plaintext: Vec<u8>, is_keepalive: bool) -> Result<()> {
        // Check state
        let state = *self.state.read().unwrap();

        if state == ConnState::Closed {
            return Err(ConnError::ConnClosed);
        }

        // If no valid session, queue the packet (unless it's a keepalive)
        if state != ConnState::Established {
            if is_keepalive {
                return Err(ConnError::NotEstablished);
            }

            // Queue the packet for later delivery
            self.pending_packets.lock().unwrap().push(plaintext);

            // Return NotEstablished to indicate packet is queued
            return Err(ConnError::NotEstablished);
        }

        // Get session and encrypt
        let (ciphertext, counter, remote_index) = {
            let session_lock = self.current.read().unwrap();
            let session = session_lock.as_ref().unwrap();
            let (ciphertext, counter) = session.encrypt(&plaintext)?;
            (ciphertext, counter, session.remote_index())
        };

        // Get remote address
        let remote_addr = self.remote_addr.read().unwrap();
        let remote_addr = remote_addr.as_ref().ok_or(ConnError::MissingRemoteAddr)?;

        // Build and send message
        let msg = build_transport_message(remote_index, counter, &ciphertext);
        self.transport.send_to(&msg, remote_addr.as_ref())?;

        // Update last sent time
        *self.last_sent.write().unwrap() = Some(Instant::now());

        Ok(())
    }

    /// Sends an empty keepalive message to the remote peer.
    /// This is used to keep NAT mappings alive and to signal liveness.
    /// Keepalives are not queued - they return an error if not established.
    pub fn send_keepalive(&self) -> Result<()> {
        self.send_payload(Vec::new(), true)
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

    /// Initiates a rekey by starting a new handshake.
    /// This is called when the current session is too old or has too many messages.
    fn initiate_rekey(&self) -> Result<()> {
        // Check if already have pending handshake
        {
            let hs = self.hs_state.read().unwrap();
            if hs.is_some() {
                return Ok(());
            }
        }

        // Get necessary data
        let remote_pk = *self.remote_pk.read().unwrap();
        let remote_addr = self.remote_addr.read().unwrap();
        let remote_addr = remote_addr.as_ref().ok_or(ConnError::MissingRemoteAddr)?;

        // Create new handshake state
        let new_idx = generate_index();
        let mut hs = HandshakeState::new(Config {
            pattern: Some(Pattern::IK),
            initiator: true,
            local_static: Some(self.local_key.clone()),
            remote_static: Some(remote_pk),
            prologue: Vec::new(),
            preshared_key: None,
        })?;

        // Generate and send handshake init message
        let msg1 = hs.write_message(&[])?;
        let ephemeral = hs.local_ephemeral().ok_or(ConnError::HandshakeFailed)?;
        let wire_msg = build_handshake_init(new_idx, &ephemeral, &msg1[KEY_SIZE..]);
        self.transport.send_to(&wire_msg, remote_addr.as_ref())?;

        // Update state
        let now = Instant::now();
        *self.hs_state.write().unwrap() = Some(hs);
        *self.handshake_started.write().unwrap() = Some(now);
        *self.handshake_attempt_start.write().unwrap() = Some(now);
        *self.last_handshake_sent.write().unwrap() = Some(now);
        *self.is_initiator.write().unwrap() = true;
        *self.rekey_triggered.write().unwrap() = true;

        Ok(())
    }

    /// Retransmits the handshake initiation with a new ephemeral key.
    /// According to WireGuard, each retransmit generates new ephemeral keys.
    fn retransmit_handshake(&self) -> Result<()> {
        // Check if we have a pending handshake
        {
            let hs = self.hs_state.read().unwrap();
            if hs.is_none() {
                return Ok(());
            }
        }

        // Get necessary data
        let remote_pk = *self.remote_pk.read().unwrap();
        let remote_addr = self.remote_addr.read().unwrap();
        let remote_addr = remote_addr.as_ref().ok_or(ConnError::MissingRemoteAddr)?;

        // Create new handshake state with new ephemeral key
        let mut hs = HandshakeState::new(Config {
            pattern: Some(Pattern::IK),
            initiator: true,
            local_static: Some(self.local_key.clone()),
            remote_static: Some(remote_pk),
            prologue: Vec::new(),
            preshared_key: None,
        })?;

        // Generate and send handshake init message
        let msg1 = hs.write_message(&[])?;
        let ephemeral = hs.local_ephemeral().ok_or(ConnError::HandshakeFailed)?;
        let wire_msg = build_handshake_init(self.local_idx, &ephemeral, &msg1[KEY_SIZE..]);
        self.transport.send_to(&wire_msg, remote_addr.as_ref())?;

        // Update state
        let now = Instant::now();
        *self.hs_state.write().unwrap() = Some(hs);
        *self.last_handshake_sent.write().unwrap() = Some(now);

        Ok(())
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
        self.tick_at(Instant::now())
    }

    /// Tick with an explicit time point. Used by tests to avoid
    /// `Instant::now() - Duration` overflow on Windows where Instant
    /// starts from process creation time.
    pub fn tick_at(&self, now: Instant) -> Result<()> {
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

                // Check if we need to retransmit handshake (every RekeyTimeout = 5s)
                let has_hs_state = self.hs_state.read().unwrap().is_some();
                if has_hs_state {
                    if let Some(last_sent) = *self.last_handshake_sent.read().unwrap() {
                        if now.duration_since(last_sent) > REKEY_TIMEOUT {
                            self.retransmit_handshake()?;
                        }
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

                // Check if we're waiting for rekey response (have pending handshake)
                let has_hs_state = self.hs_state.read().unwrap().is_some();
                if has_hs_state {
                    // Check if handshake attempt has exceeded RekeyAttemptTime (90s)
                    if let Some(start) = *self.handshake_attempt_start.read().unwrap() {
                        if now.duration_since(start) > REKEY_ATTEMPT_TIME {
                            return Err(ConnError::HandshakeTimeout);
                        }
                    }

                    // Check if we need to retransmit handshake (every RekeyTimeout = 5s)
                    if let Some(last_sent) = *self.last_handshake_sent.read().unwrap() {
                        if now.duration_since(last_sent) > REKEY_TIMEOUT {
                            self.retransmit_handshake()?;
                        }
                    }
                    return Ok(());
                }

                // Disconnection detection (WireGuard Section 5):
                // If no packets received for KeepaliveTimeout + RekeyTimeout (15s),
                // initiate a new handshake to re-establish connection
                let is_initiator = *self.is_initiator.read().unwrap();
                let disconnection_threshold = KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;
                if is_initiator {
                    if let Some(last_recv) = *self.last_received.read().unwrap() {
                        if now.duration_since(last_recv) > disconnection_threshold {
                            self.initiate_rekey()?;
                            return Ok(());
                        }
                    }
                }

                // Check if rekey is needed (session too old or too many messages, initiator only)
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
                        if send_nonce > REKEY_AFTER_MESSAGES {
                            needs_rekey = true;
                        }
                    }

                    if needs_rekey {
                        self.initiate_rekey()?;
                        return Ok(());
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
                        let _ = self.send_keepalive();
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

    // ============================================
    // Tick tests
    // ============================================

    #[test]
    fn test_tick_new_conn() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: None,
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        // Tick on new connection should succeed
        assert!(conn.tick().is_ok());
    }

    #[test]
    fn test_tick_closed_conn() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: None,
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        conn.close().unwrap();

        // Tick on closed connection should fail
        let err = conn.tick().unwrap_err();
        assert!(matches!(err, ConnError::InvalidState));
    }

    #[test]
    fn test_tick_conn_timeout() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        let server_key = KeyPair::generate();

        let session = Session::new(SessionConfig {
            local_index: 1,
            remote_index: 2,
            send_key: Key::from([1u8; KEY_SIZE]),
            recv_key: Key::from([2u8; KEY_SIZE]),
            remote_pk: server_key.public,
        });
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: Some(server_key.public),
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        // Manually set established state with current time for lastReceived,
        // then tick_at a future time that exceeds REJECT_AFTER_TIME.
        let base = Instant::now();
        *conn.state.write().unwrap() = ConnState::Established;
        *conn.current.write().unwrap() = Some(session);
        *conn.last_sent.write().unwrap() = Some(base);
        *conn.last_received.write().unwrap() = Some(base);
        *conn.session_created.write().unwrap() = Some(base);

        let future = base + REJECT_AFTER_TIME + std::time::Duration::from_secs(1);
        let err = conn.tick_at(future).unwrap_err();
        assert!(matches!(err, ConnError::ConnTimeout));
    }

    #[test]
    fn test_tick_handshake_timeout() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: None,
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        // Manually set handshaking state with current time for attempt start,
        // then tick_at a future time that exceeds REKEY_ATTEMPT_TIME.
        let base = Instant::now();
        *conn.state.write().unwrap() = ConnState::Handshaking;
        *conn.handshake_attempt_start.write().unwrap() = Some(base);

        let future = base + REKEY_ATTEMPT_TIME + std::time::Duration::from_secs(1);
        let err = conn.tick_at(future).unwrap_err();
        assert!(matches!(err, ConnError::HandshakeTimeout));
    }

    #[test]
    fn test_tick_no_action_when_recent() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        let server_key = KeyPair::generate();

        let session = Session::new(SessionConfig {
            local_index: 1,
            remote_index: 2,
            send_key: Key::from([1u8; KEY_SIZE]),
            recv_key: Key::from([2u8; KEY_SIZE]),
            remote_pk: server_key.public,
        });
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: Some(server_key.public),
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        let now = Instant::now();
        *conn.state.write().unwrap() = ConnState::Established;
        *conn.current.write().unwrap() = Some(session);
        *conn.last_sent.write().unwrap() = Some(now);
        *conn.last_received.write().unwrap() = Some(now);
        *conn.session_created.write().unwrap() = Some(now);

        // Tick should succeed without any action
        assert!(conn.tick().is_ok());
    }

    #[test]
    fn test_tick_responder_no_rekey() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        let server_key = KeyPair::generate();

        let session = Session::new(SessionConfig {
            local_index: 1,
            remote_index: 2,
            send_key: Key::from([1u8; KEY_SIZE]),
            recv_key: Key::from([2u8; KEY_SIZE]),
            remote_pk: server_key.public,
        });
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: Some(server_key.public),
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        let now = Instant::now();
        *conn.state.write().unwrap() = ConnState::Established;
        *conn.current.write().unwrap() = Some(session);
        *conn.is_initiator.write().unwrap() = false; // Responder
        *conn.last_sent.write().unwrap() = Some(now);
        *conn.last_received.write().unwrap() = Some(now);
        // Old session (past RekeyAfterTime)
        *conn.session_created.write().unwrap() = Some(now - REKEY_AFTER_TIME - std::time::Duration::from_secs(1));

        assert!(conn.tick().is_ok());

        // Responder should NOT trigger rekey
        assert!(conn.hs_state.read().unwrap().is_none());
    }

    #[test]
    fn test_tick_rekey_not_duplicate() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        let server_key = KeyPair::generate();

        let session = Session::new(SessionConfig {
            local_index: 1,
            remote_index: 2,
            send_key: Key::from([1u8; KEY_SIZE]),
            recv_key: Key::from([2u8; KEY_SIZE]),
            remote_pk: server_key.public,
        });
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: Some(server_key.public),
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        let now = Instant::now();
        *conn.state.write().unwrap() = ConnState::Established;
        *conn.current.write().unwrap() = Some(session);
        *conn.is_initiator.write().unwrap() = true;
        *conn.rekey_triggered.write().unwrap() = true; // Already triggered
        *conn.last_sent.write().unwrap() = Some(now);
        *conn.last_received.write().unwrap() = Some(now);
        *conn.session_created.write().unwrap() = Some(now - REKEY_AFTER_TIME - std::time::Duration::from_secs(1));

        assert!(conn.tick().is_ok());

        // Should NOT trigger rekey again when already triggered
        assert!(conn.hs_state.read().unwrap().is_none());
    }

    #[test]
    fn test_tick_no_keepalive_when_no_recent_receive() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        let server_key = KeyPair::generate();

        let session = Session::new(SessionConfig {
            local_index: 1,
            remote_index: 2,
            send_key: Key::from([1u8; KEY_SIZE]),
            recv_key: Key::from([2u8; KEY_SIZE]),
            remote_pk: server_key.public,
        });
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: Some(server_key.public),
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        let now = Instant::now();
        let old_time = now - KEEPALIVE_TIMEOUT - std::time::Duration::from_secs(1);
        
        *conn.state.write().unwrap() = ConnState::Established;
        *conn.current.write().unwrap() = Some(session);
        // Both old -> no keepalive
        *conn.last_sent.write().unwrap() = Some(old_time);
        *conn.last_received.write().unwrap() = Some(old_time);
        *conn.session_created.write().unwrap() = Some(now);

        let original_last_sent = old_time;
        assert!(conn.tick().is_ok());

        // lastSent should NOT have been updated
        let last_sent = conn.last_sent.read().unwrap().unwrap();
        assert_eq!(last_sent, original_last_sent);
    }

    #[test]
    fn test_send_keepalive_not_established() {
        let key = KeyPair::generate();
        let transport = MockTransport::new("test");
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: None,
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        // Send keepalive on non-established connection should fail
        let err = conn.send_keepalive().unwrap_err();
        assert!(matches!(err, ConnError::NotEstablished));
    }

    // ============================================
    // Disconnection detection tests
    // ============================================

    #[test]
    fn test_tick_disconnection_detection_initiator() {
        // Test that initiator detects disconnection when no packets received
        // for KeepaliveTimeout + RekeyTimeout (15s) and initiates new handshake
        let key = KeyPair::generate();
        let server_key = KeyPair::generate();

        let client_transport = MockTransport::new("client");
        let server_transport = MockTransport::new("server");
        MockTransport::connect(&client_transport, &server_transport);

        let session = Session::new(SessionConfig {
            local_index: 1,
            remote_index: 2,
            send_key: Key::from([1u8; KEY_SIZE]),
            recv_key: Key::from([2u8; KEY_SIZE]),
            remote_pk: server_key.public,
        });
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: Some(server_key.public),
            transport: Arc::clone(&client_transport),
            remote_addr: Some(Box::new(MockAddr::new("server"))),
        }).unwrap();

        // Set as initiator with no recent received data (past disconnection threshold)
        let disconnection_threshold = KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;
        let now = Instant::now();
        *conn.state.write().unwrap() = ConnState::Established;
        *conn.current.write().unwrap() = Some(session);
        *conn.is_initiator.write().unwrap() = true;
        *conn.last_sent.write().unwrap() = Some(now);
        *conn.last_received.write().unwrap() = Some(now - disconnection_threshold - std::time::Duration::from_secs(1));
        *conn.session_created.write().unwrap() = Some(now);

        // Tick should detect disconnection and initiate rekey
        assert!(conn.tick().is_ok());

        // Verify that a new handshake was initiated
        assert!(conn.hs_state.read().unwrap().is_some(), 
            "Initiator should initiate new handshake on disconnection detection");
        assert!(*conn.rekey_triggered.read().unwrap(),
            "rekeyTriggered should be set on disconnection detection");
    }

    #[test]
    fn test_tick_disconnection_detection_responder_no_action() {
        // Test that responder does NOT initiate handshake on disconnection
        // (only initiator is responsible for re-establishing connection)
        let key = KeyPair::generate();
        let server_key = KeyPair::generate();
        let transport = MockTransport::new("test");

        let session = Session::new(SessionConfig {
            local_index: 1,
            remote_index: 2,
            send_key: Key::from([1u8; KEY_SIZE]),
            recv_key: Key::from([2u8; KEY_SIZE]),
            remote_pk: server_key.public,
        });
        
        let conn = Conn::new(ConnConfig {
            local_key: key,
            remote_pk: Some(server_key.public),
            transport: Arc::clone(&transport),
            remote_addr: None,
        }).unwrap();

        // Set as responder with no recent received data
        let disconnection_threshold = KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;
        let now = Instant::now();
        *conn.state.write().unwrap() = ConnState::Established;
        *conn.current.write().unwrap() = Some(session);
        *conn.is_initiator.write().unwrap() = false; // Responder
        *conn.last_sent.write().unwrap() = Some(now);
        *conn.last_received.write().unwrap() = Some(now - disconnection_threshold - std::time::Duration::from_secs(1));
        *conn.session_created.write().unwrap() = Some(now);

        assert!(conn.tick().is_ok());

        // Responder should NOT initiate handshake
        assert!(conn.hs_state.read().unwrap().is_none(),
            "Responder should NOT initiate handshake on disconnection");
    }
}
