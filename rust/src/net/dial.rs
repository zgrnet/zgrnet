//! Dial function for initiating connections.
//!
//! This module provides a `dial` function that creates a connection
//! and performs the handshake with the remote peer using WireGuard-style
//! retry mechanism.

use std::io::ErrorKind;
use std::time::Instant;

use crate::noise::{
    build_handshake_init, parse_handshake_resp, Addr, Config, HandshakeState, Key, KeyPair,
    Pattern, Session, SessionConfig, Transport, TransportError, MAX_PACKET_SIZE, KEY_SIZE,
};

use super::conn::{Conn, ConnConfig, ConnError, ConnState, Result};
use super::consts::{REKEY_ATTEMPT_TIME, REKEY_TIMEOUT};

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
    /// Deadline for the dial operation.
    /// If None, defaults to now + REKEY_ATTEMPT_TIME (90s).
    pub deadline: Option<Instant>,
}

/// Dials a remote peer and returns an established connection.
///
/// This implements WireGuard's retry mechanism:
/// - Sends handshake initiation
/// - Waits up to REKEY_TIMEOUT (5s) for response
/// - Retransmits with new ephemeral keys on timeout
/// - Gives up after deadline is reached
///
/// # Example
///
/// ```ignore
/// let conn = dial(DialOptions {
///     local_key,
///     remote_pk,
///     transport,
///     remote_addr: Box::new(addr),
///     deadline: None,
/// })?;
/// ```
pub fn dial<T: Transport + 'static>(opts: DialOptions<T>) -> Result<Conn<T>> {
    // Validate inputs
    if opts.remote_pk.is_zero() {
        return Err(ConnError::MissingRemotePK);
    }

    let deadline = opts.deadline.unwrap_or_else(|| Instant::now() + REKEY_ATTEMPT_TIME);
    let local_key = opts.local_key;
    let remote_pk = opts.remote_pk;
    let transport = opts.transport;
    let remote_addr = opts.remote_addr;

    // Create the connection in New state
    let conn = Conn::new(ConnConfig {
        local_key: local_key.clone(),
        remote_pk: Some(remote_pk),
        transport,
        remote_addr: Some(remote_addr.clone_box()),
    })?;

    // Get local index for handshake
    let local_idx = conn.local_index();

    // Set state to handshaking
    conn.set_state(ConnState::Handshaking);

    // Retry loop with fresh ephemeral keys each attempt
    loop {
        // Check deadline
        if Instant::now() >= deadline {
            conn.set_state(ConnState::New);
            return Err(ConnError::HandshakeTimeout);
        }

        // Create fresh handshake state with new ephemeral keys
        let mut hs = match HandshakeState::new(Config {
            pattern: Some(Pattern::IK),
            initiator: true,
            local_static: Some(local_key.clone()),
            remote_static: Some(remote_pk),
            ..Default::default()
        }) {
            Ok(hs) => hs,
            Err(e) => {
                conn.set_state(ConnState::New);
                return Err(e.into());
            }
        };

        // Generate handshake initiation message
        let msg1 = match hs.write_message(&[]) {
            Ok(msg) => msg,
            Err(e) => {
                conn.set_state(ConnState::New);
                return Err(e.into());
            }
        };

        // Build wire message: ephemeral(32) + encrypted_static(48) = 80 bytes
        let wire_msg = build_handshake_init(local_idx, &hs.local_ephemeral().unwrap(), &msg1[KEY_SIZE..]);

        // Send handshake initiation
        if let Err(e) = conn.transport().send_to(&wire_msg, remote_addr.as_ref()) {
            conn.set_state(ConnState::New);
            return Err(e.into());
        }

        // Calculate read deadline: min(now + REKEY_TIMEOUT, total deadline)
        let read_deadline = std::cmp::min(Instant::now() + REKEY_TIMEOUT, deadline);

        // Set read deadline on transport
        let _ = conn.transport().set_read_deadline(Some(read_deadline));

        // Wait for handshake response
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let recv_result = conn.transport().recv_from(&mut buf);

        // Clear deadline
        let _ = conn.transport().set_read_deadline(None);

        // Handle receive result
        let (n, _from) = match recv_result {
            Ok(result) => result,
            Err(TransportError::Io(ref e)) if is_timeout_error(e) => {
                // Timeout - retry with new ephemeral keys
                continue;
            }
            Err(e) => {
                conn.set_state(ConnState::New);
                return Err(e.into());
            }
        };

        // Parse response
        let resp = match parse_handshake_resp(&buf[..n]) {
            Ok(resp) => resp,
            Err(e) => {
                conn.set_state(ConnState::New);
                return Err(e.into());
            }
        };

        // Verify receiver index matches our sender index
        if resp.receiver_index != local_idx {
            conn.set_state(ConnState::New);
            return Err(ConnError::InvalidReceiverIndex);
        }

        // Reconstruct the noise message and process
        let mut noise_msg = vec![0u8; KEY_SIZE + 16];
        noise_msg[..KEY_SIZE].copy_from_slice(resp.ephemeral.as_bytes());
        noise_msg[KEY_SIZE..].copy_from_slice(&resp.empty_encrypted);

        if let Err(e) = hs.read_message(&noise_msg) {
            conn.set_state(ConnState::New);
            return Err(e.into());
        }

        // Complete handshake - create session
        if !hs.is_finished() {
            conn.set_state(ConnState::New);
            return Err(ConnError::HandshakeIncomplete);
        }

        // Get transport keys
        let (send_cipher, recv_cipher) = match hs.split() {
            Ok(ciphers) => ciphers,
            Err(e) => {
                conn.set_state(ConnState::New);
                return Err(e.into());
            }
        };

        // Create session
        let session = Session::new(SessionConfig {
            local_index: local_idx,
            remote_index: resp.sender_index,
            send_key: *send_cipher.key(),
            recv_key: *recv_cipher.key(),
            remote_pk,
        });

        // Set session and state on connection
        conn.set_session(session);
        conn.set_state(ConnState::Established);

        return Ok(conn);
    }
}

/// Checks if an I/O error is a timeout error.
fn is_timeout_error(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::MockTransport;

    #[test]
    fn test_dial_missing_remote_pk() {
        let local_key = KeyPair::generate();
        let transport = MockTransport::new("test");

        let result = dial(DialOptions {
            local_key,
            remote_pk: Key::default(),
            transport,
            remote_addr: Box::new(crate::noise::MockAddr::new("peer")),
            deadline: None,
        });

        assert!(matches!(result, Err(ConnError::MissingRemotePK)));
    }
}
