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

pub use keypair::{Key, KeyPair};
pub use cipher::{Hash, HASH_SIZE, TAG_SIZE};
pub use state::{CipherState, SymmetricState};
pub use handshake::{HandshakeState, Config, Pattern, Error};
