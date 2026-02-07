//! SOCKS5 and HTTP CONNECT proxy servers.
//!
//! This module implements:
//! - SOCKS5 TCP CONNECT and UDP ASSOCIATE
//! - HTTP CONNECT proxy (auto-detected on same port)
//! - Remote TCP_PROXY and UDP_PROXY handlers for exit nodes

mod socks5;
mod handler;

pub use socks5::*;
pub use handler::*;
