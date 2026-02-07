//! Noise Protocol implementation.
//!
//! This module provides a pure Noise Protocol Framework implementation
//! supporting IK, XX, and NN handshake patterns.

mod keypair;
pub mod cipher;
mod state;
mod handshake;
mod replay;
mod session;
pub mod message;
pub mod transport;
pub mod address;

pub use keypair::{Key, KeyPair, KEY_SIZE};
pub use cipher::{Hash, HASH_SIZE, TAG_SIZE};
pub use state::{CipherState, SymmetricState};
pub use handshake::{Config, Error, HandshakeState, Pattern};
pub use replay::ReplayFilter;
pub use session::{generate_index, Session, SessionConfig, SessionError, SessionState};

// Re-export message types
pub use message::{
    build_handshake_init, build_handshake_resp, build_transport_message, decode_payload,
    encode_payload, parse_handshake_init, parse_handshake_resp, parse_transport_message,
    HandshakeInit, HandshakeResp, MessageError, TransportMessage, MAX_PACKET_SIZE,
    protocol,
};

// Re-export address types
pub use address::{Address, AddressError, ATYP_IPV4, ATYP_DOMAIN, ATYP_IPV6};

// Re-export transport types
pub use transport::{Addr, MockAddr, MockTransport, Transport, TransportError};
