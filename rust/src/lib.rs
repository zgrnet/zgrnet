//! Noise Protocol implementation for zgrnet.
//!
//! This crate provides a pure Noise Protocol Framework implementation
//! supporting IK, XX, and NN handshake patterns.
//!
//! # Example
//!
//! ```rust
//! use noise::{KeyPair, HandshakeState, Config, Pattern};
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

mod keypair;
pub mod cipher;
mod state;
mod handshake;
mod replay;
mod session;
mod manager;
pub mod message;
pub mod transport;
pub mod conn;
pub mod udp;

pub use keypair::{Key, KeyPair};
pub use cipher::{Hash, HASH_SIZE, TAG_SIZE};
pub use state::{CipherState, SymmetricState};
pub use handshake::{HandshakeState, Config, Pattern, Error};
pub use replay::ReplayFilter;
pub use session::{Session, SessionConfig, SessionState, SessionError, generate_index};
pub use manager::{SessionManager, ManagerError};

// Conn layer exports
pub use message::{
    HandshakeInit, HandshakeResp, TransportMessage, MessageError,
    parse_handshake_init, parse_handshake_resp, parse_transport_message,
    build_handshake_init, build_handshake_resp, build_transport_message,
    encode_payload, decode_payload,
};
pub use transport::{Addr, Transport, TransportError, MockAddr, MockTransport};
pub use conn::{Conn, ConnConfig, ConnState, ConnError};
