//! Connection management for Noise-based communication.
//!
//! This module provides WireGuard-style connection management including:
//! - `Conn`: A connection to a remote peer
//! - `Listener`: Server-side connection acceptor
//! - `dial`: Client-side connection initiator
//! - `SessionManager`: Multi-peer session management
//! - Timer constants based on WireGuard's timing parameters

mod conn;
mod consts;
mod dial;
mod listener;
mod manager;

pub use conn::{Conn, ConnConfig, ConnError, ConnState};
pub use consts::{
    KEEPALIVE_TIMEOUT, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME, REKEY_ATTEMPT_TIME,
    REKEY_ON_RECV_THRESHOLD, REKEY_TIMEOUT, REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME,
    SESSION_CLEANUP_TIME,
};
pub use dial::{dial, DialOptions};
pub use listener::{Listener, ListenerConfig, ListenerError};
pub use manager::{ManagerError, SessionManager};
