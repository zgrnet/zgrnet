//! Relay protocol implementation for multi-hop forwarding.
//!
//! This module implements RELAY_0/1/2 (protocol 66/67/68) and
//! PING/PONG (protocol 70/71) message encoding/decoding and
//! forwarding logic.
//!
//! The relay engine is pure logic with no I/O. It returns `Action`s
//! that the caller (UDP/Host) executes.

mod message;
mod engine;

pub use message::*;
pub use engine::*;
