//! Connection management for Noise-based communication.
//!
//! This module provides WireGuard-style connection management including:
//! - `Conn`: A connection to a remote peer
//! - `Listener`: Server-side connection acceptor
//! - `dial`: Client-side connection initiator
//! - `SessionManager`: Multi-peer session management
//! - Timer constants based on WireGuard's timing parameters

const std = @import("std");

pub const conn_impl = @import("conn.zig");
pub const consts = @import("consts.zig");
pub const dial_mod = @import("dial.zig");
pub const listener_mod = @import("listener.zig");
pub const manager = @import("manager.zig");

// Re-export main types
pub const Conn = conn_impl.Conn;
pub const ConnConfig = conn_impl.ConnConfig;
pub const ConnState = conn_impl.ConnState;
pub const ConnError = conn_impl.ConnError;
pub const RecvResult = conn_impl.RecvResult;

// Re-export dial function and options
pub const dial = dial_mod.dial;
pub const DialOptions = dial_mod.DialOptions;
pub const DialError = dial_mod.DialError;

// Re-export listener types
pub const Listener = listener_mod.Listener;
pub const ListenerConfig = listener_mod.ListenerConfig;
pub const ListenerError = listener_mod.ListenerError;

pub const SessionManager = manager.SessionManager;
pub const ManagerError = manager.ManagerError;

// Re-export constants
pub const rekey_after_time_ns = consts.rekey_after_time_ns;
pub const reject_after_time_ns = consts.reject_after_time_ns;
pub const rekey_attempt_time_ns = consts.rekey_attempt_time_ns;
pub const rekey_timeout_ns = consts.rekey_timeout_ns;
pub const keepalive_timeout_ns = consts.keepalive_timeout_ns;
pub const rekey_on_recv_threshold_ns = consts.rekey_on_recv_threshold_ns;
pub const session_cleanup_time_ns = consts.session_cleanup_time_ns;
pub const rekey_after_messages = consts.rekey_after_messages;
pub const reject_after_messages = consts.reject_after_messages;

test {
    std.testing.refAllDecls(@This());
    _ = conn_impl;
    _ = consts;
    _ = dial_mod;
    _ = listener_mod;
    _ = manager;
}
