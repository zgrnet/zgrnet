//! Network layer for zgrnet.
//!
//! This module provides:
//! - `Conn`: A connection to a remote peer (WireGuard-style)
//! - `Listener`: Server-side connection acceptor
//! - `dial`: Client-side connection initiator
//! - `SessionManager`: Multi-peer session management
//! - `UdpTransport`: UDP-based transport implementation
//! - `UDP`: High-level peer management layer
//!
//! Timer constants based on WireGuard's timing parameters are also exported.

mod async_udp;
mod conn;
mod consts;
mod dial;
mod listener;
mod manager;
mod transport_udp;
mod udp;

// Connection management exports
pub use conn::{Conn, ConnConfig, ConnError, ConnState};
pub use consts::{
    KEEPALIVE_TIMEOUT, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME, REKEY_ATTEMPT_TIME,
    REKEY_ON_RECV_THRESHOLD, REKEY_TIMEOUT, REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME,
    SESSION_CLEANUP_TIME,
};
pub use dial::{dial, DialOptions};
pub use listener::{Listener, ListenerConfig, ListenerError};
pub use manager::{ManagerError, SessionManager};

// Transport exports
pub use transport_udp::UdpTransport;

// High-level UDP API exports
pub use udp::{HostInfo, Peer, PeerInfo, PeerState, UdpError, UdpOptions, UDP};

// Re-export KCP Stream for convenience
pub use crate::kcp::Stream;

// Async UDP exports
pub use async_udp::{AsyncUDP, AsyncUdpConfig, DecryptedPacket, RawPacket};
