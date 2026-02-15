//! zgrnet - Noise Protocol based networking library.
//!
//! This crate provides:
//! - `noise`: Pure Noise Protocol Framework implementation
//! - `net`: Network layer with WireGuard-style connection management
//!
//! # Example
//!
//! ```rust,ignore
//! use zgrnet::noise::{KeyPair, HandshakeState, Config, Pattern};
//!
//! // Generate key pairs
//! let initiator_static = KeyPair::generate();
//! let responder_static = KeyPair::generate();
//!
//! // Create handshake (IK pattern)
//! let mut initiator = HandshakeState::new(Config {
//!     pattern: Some(Pattern::IK),
//!     initiator: true,
//!     local_static: Some(initiator_static),
//!     remote_static: Some(responder_static.public),
//!     ..Default::default()
//! }).unwrap();
//! ```

pub mod noise;
pub mod net;
pub mod kcp;
pub mod relay;
pub mod host;
pub mod node;
pub mod proxy;
pub mod dns;
pub mod config;
pub mod api;
pub mod cli;
pub mod lan;

#[cfg(feature = "tun")]
pub mod tun;

#[cfg(feature = "dnsmgr")]
pub mod dnsmgr;

// Re-export commonly used types at crate root for convenience
pub use noise::{
    // Core types
    Key, KeyPair, KEY_SIZE,
    Hash, HASH_SIZE, TAG_SIZE,
    CipherState, SymmetricState,
    HandshakeState, Config, Pattern, Error,
    ReplayFilter,
    Session, SessionConfig, SessionState, SessionError, generate_index,
    // Message types
    HandshakeInit, HandshakeResp, TransportMessage, MessageError,
    parse_handshake_init, parse_handshake_resp, parse_transport_message,
    build_handshake_init, build_handshake_resp, build_transport_message,
    encode_payload, decode_payload, MAX_PACKET_SIZE,
    // Transport types
    Addr, Transport, TransportError, MockAddr, MockTransport,
};

pub use net::{
    // Connection management
    Conn, ConnConfig, ConnState, ConnError,
    Listener, ListenerConfig, ListenerError,
    dial, DialOptions,
    SessionManager, ManagerError,
    // Timer constants
    KEEPALIVE_TIMEOUT, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME, REKEY_ATTEMPT_TIME,
    REKEY_ON_RECV_THRESHOLD, REKEY_TIMEOUT, REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME,
    SESSION_CLEANUP_TIME,
    // Transport
    UdpTransport,
    // High-level UDP API
    UDP, UdpOptions, UdpError, HostInfo, PeerInfo, Peer, PeerState,
    // Async UDP pipeline API
    AsyncUDP, AsyncUdpConfig, DecryptedPacket, RawPacket,
};

// KCP and stream multiplexing
pub use kcp::{
    Kcp, Frame, Cmd, FrameError, FRAME_HEADER_SIZE, MAX_PAYLOAD_SIZE,
    Stream, StreamState, StreamError, Mux, MuxConfig, MuxError,
};
