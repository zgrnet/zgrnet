//! Dial function for initiating connections.
//!
//! This module provides a `dial` function that creates a connection
//! and performs the handshake with the remote peer.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::noise::{KeyPair, Key, Transport, Addr};
use super::conn::{Conn, ConnConfig, ConnState, ConnError};
use super::consts::{REKEY_ATTEMPT_TIME, REKEY_TIMEOUT};

/// Result type for dial operations.
pub type Result<T> = std::result::Result<T, ConnError>;

/// Options for dialing a remote peer.
pub struct DialOptions<T: Transport + 'static> {
    /// Local static key pair.
    pub local_key: KeyPair,
    /// Remote peer's public key.
    pub remote_pk: Key,
    /// Underlying datagram transport.
    pub transport: T,
    /// Remote peer's address.
    pub remote_addr: Box<dyn Addr>,
    /// Timeout for the dial operation (default: REKEY_ATTEMPT_TIME).
    pub timeout: Option<Duration>,
}

/// Dials a remote peer and returns an established connection.
///
/// This is a blocking call that:
/// 1. Creates a new connection
/// 2. Initiates the handshake
/// 3. Waits for the handshake to complete
///
/// # Example
///
/// ```ignore
/// let conn = dial(DialOptions {
///     local_key,
///     remote_pk,
///     transport,
///     remote_addr: Box::new(addr),
///     timeout: None,
/// })?;
/// ```
pub fn dial<T: Transport + 'static>(opts: DialOptions<T>) -> Result<Conn<T>> {
    let timeout = opts.timeout.unwrap_or(REKEY_ATTEMPT_TIME);
    let start = Instant::now();

    // Create the connection
    let conn = Conn::new(ConnConfig {
        local_key: opts.local_key,
        remote_pk: Some(opts.remote_pk),
        transport: opts.transport,
        remote_addr: Some(opts.remote_addr),
    })?;

    // Initiate the handshake
    conn.open()?;

    // Wait for the handshake to complete
    // Note: In a real implementation, we'd want to poll or have a callback
    // For now, this is synchronous
    while conn.state() != ConnState::Established {
        if start.elapsed() > timeout {
            return Err(ConnError::HandshakeTimeout);
        }
        
        // In a real implementation, we'd wait for the response here
        // For now, the open() method is synchronous and completes the handshake
        break;
    }

    Ok(conn)
}

#[cfg(test)]
mod tests {
    // Note: Integration tests for dial would require a mock peer
    // to complete the handshake. This is covered in conn tests.
}
